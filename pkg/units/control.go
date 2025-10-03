// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package units implements the business logic to make the fuzzer work
package units

import (
	"buzzer/pkg/cbpf/cbpf"
	"buzzer/pkg/ebpf/ebpf"
	cpb "buzzer/proto/cbpf_go_proto"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
	"errors"
	"fmt"
)

var (
	NilStrategyError = errors.New("Strategy cannot be nil")
)

// StrategyInterface contains all the methods that a fuzzing strategy should
// implement.
type Strategy interface {
	// GenerateProgram should return the instructions to feed the verifier.
	GenerateProgram(ffi *FFI) (*pb.Program, error)

	// OnVerifyDone process the results from the verifier. Here the strategy
	// can also tell the fuzzer to continue with execution by returning true
	// or start over and generate a new program.
	OnVerifyDone(ffi *FFI, verificationResult *fpb.ValidationResult) bool

	// OnExecuteDone should validate if the program behaved like the
	// verifier expected, if that was not the case it should return false.
	OnExecuteDone(ffi *FFI, executionResult *fpb.ExecutionResult) bool

	// OnError is used to determine if the fuzzer should continue on errors.
	// true represents continue, false represents halt.
	OnError(e error) bool

	// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
	// and return normally.
	IsFuzzingDone() bool

	// Name returns the name of the current strategy to be able
	// to select it with the command line flag.
	Name() string
}

// Control directs the execution of the fuzzer.
type Control struct {
	strat Strategy
	ffi   *FFI
	cm    *CoverageManager
	rdy   bool
}

// Init prepares the control unit to be used.
func (cu *Control) Init(ffi *FFI, coverageManager *CoverageManager, strat Strategy) error {

	if strat == nil {
		return NilStrategyError
	}
	cu.ffi = ffi
	cu.cm = coverageManager
	cu.strat = strat
	cu.rdy = true
	return nil
}

// IsReady indicates to the caller if the Control is initialized successully.
func (cu *Control) IsReady() bool {
	return cu.rdy
}

// RunFuzzer kickstars the fuzzer in the mode that was specified at Init time.
func (cu *Control) RunFuzzer() error {
	for !cu.strat.IsFuzzingDone() {
		prog, err := cu.strat.GenerateProgram(cu.ffi)
		if err != nil {
			fmt.Printf("Generate program error: %v\n", err)
			if !cu.strat.OnError(err) {
				return err
			}
			continue
		}

		switch p := prog.Program.(type) {
		case *pb.Program_Cbpf:
			err := cu.runCbpf(p.Cbpf)
			if err != nil {
				if !cu.strat.OnError(err) {
					return err
				}
				continue
			}

		case *pb.Program_Ebpf:
			err := cu.runEbpf(p.Ebpf)
			if err != nil {
				if !cu.strat.OnError(err) {
					return err
				}
				continue
			}
		}

	}
	return nil
}

func (cu *Control) runEbpf(prog *epb.Program) error {
	encodedProg, encodedFuncInfo, err := ebpf.EncodeInstructions(prog)

	if err != nil {
		fmt.Printf("Encoding error: %v\n", err)
		if !cu.strat.OnError(err) {
			return err
		}
	}

	encodedProgram := &fpb.EncodedProgram{
		Program:  encodedProg,
		Btf:      prog.Btf,
		Function: encodedFuncInfo,
		Maps:     prog.Maps,
	}
	validationResult, err := cu.ffi.ValidateEbpfProgram(encodedProgram)
	defer func() {
		cu.ffi.CleanFdArray(validationResult.FdArrayAddr, len(prog.Maps))
	}()
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		if !cu.strat.OnError(err) {
			return err
		}
		return nil
	}

	if !cu.strat.OnVerifyDone(cu.ffi, validationResult) || !validationResult.IsValid {
		cu.ffi.CloseFD(int(validationResult.ProgramFd))
		return nil
	}

	exReq := &fpb.ExecutionRequest{
		ProgFd: validationResult.ProgramFd,
	}

	exRes, err := cu.ffi.RunEbpfProgram(exReq)
	defer func() {
		cu.ffi.CloseFD(int(validationResult.ProgramFd))
	}()
	if err != nil {
		fmt.Printf("RunProgram error: %v\n", err)
		if !cu.strat.OnError(err) {
			return err
		}
		return nil
	}

	exRes.FdArray = validationResult.FdArrayAddr

	ok := cu.strat.OnExecuteDone(cu.ffi, exRes)
	if !ok {
		fmt.Println("Program produced unexpected results")
		ebpf.GeneratePoc(prog)
	}
	return nil
}

func (cu *Control) runCbpf(prog *cpb.Program) error {
	encodedProg := encodeCbpfInstructions(prog)
	validationResult, err := cu.ffi.ValidateCbpfProgram(encodedProg)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		if !cu.strat.OnError(err) {
			return err
		}
		return nil
	}

	if !cu.strat.OnVerifyDone(cu.ffi, validationResult) || !validationResult.IsValid {
		cu.ffi.CloseFD(int(validationResult.ProgramFd))
		return nil
	}

	exReq := &fpb.CbpfExecutionRequest{
		SocketWrite: validationResult.SocketWrite,
		SocketRead:  validationResult.SocketRead,
	}

	exRes, err := cu.ffi.RunCbpfProgram(exReq)
	if err != nil {
		fmt.Printf("RunProgram error: %v\n", err)
		if !cu.strat.OnError(err) {
			return err
		}
		return nil
	}

	ok := cu.strat.OnExecuteDone(cu.ffi, exRes)
	if !ok {
		fmt.Println("Program produced unexpected results")
	}
	return nil
}

// Encode proto program instructions into their correct structure.
// https://www.infradead.org/~mchehab/kernel_docs/networking/filter.html#structure
func encodeCbpfInstructions(program *cpb.Program) []cbpf.Filter {
	result := []cbpf.Filter{}
	for _, instruction := range program.Instructions {
		ins := cbpf.Filter{
			Opcode: uint16(instruction.Opcode),
			Jt:     uint8(instruction.Jt),
			Jf:     uint8(instruction.Jf),
			K:      uint32(instruction.K),
		}

		result = append(result, ins)
	}
	return result
}
