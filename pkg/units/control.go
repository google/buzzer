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
	"fmt"

	//"buzzer/pkg/strategies/strategies"
	"buzzer/pkg/ebpf/ebpf"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
)

// StrategyInterface contains all the methods that a fuzzing strategy should
// implement.
type StrategyInterface interface {
	// GenerateProgram should return the instructions to feed the verifier.
	GenerateProgram(ffi *FFI) ([]*epb.Instruction, error)

	// OnVerifyDone process the results from the verifier.
	OnVerifyDone(verificationResult *fpb.ValidationResult)

	// OnExecuteDone should validate if the program behaved like the
	// verifier expected, if that was not the case it should return false.
	OnExecuteDone(executionResult *fpb.ExecutionResult) bool
}

// Control directs the execution of the fuzzer.
type Control struct {
	strat StrategyInterface
	ffi   *FFI
	cm    *CoverageManager
	rdy   bool
}

// Init prepares the control unit to be used.
func (cu *Control) Init(ffi *FFI, coverageManager *CoverageManager, fuzzStrategyFlag string) error {
	cu.ffi = ffi
	cu.cm = coverageManager

	switch fuzzStrategyFlag {
	default:
		return fmt.Errorf("unknown fuzzing strategy: %s", fuzzStrategyFlag)
	}

	cu.rdy = true
	return nil
}

// IsReady indicates to the caller if the Control is initialized successully.
func (cu *Control) IsReady() bool {
	return cu.rdy
}

// RunFuzzer kickstars the fuzzer in the mode that was specified at Init time.
func (cu *Control) RunFuzzer() error {
	for {
		prog, err := cu.strat.GenerateProgram(cu.ffi)
		if err != nil {
			return err
		}

		encodedProg, err := ebpf.EncodeInstructions(prog)
		if err != nil {
			return err
		}

		validationResult, err := cu.ffi.ValidateProgram(encodedProg)
		if err != nil {
			return err
		}
		cu.strat.OnVerifyDone(validationResult)

		if !validationResult.IsValid {
			continue
		}

		exReq := &fpb.ExecutionRequest{
			ProgFd: validationResult.ProgramFd,
		}
		exRes, err := cu.ffi.RunProgram(exReq)
		if err != nil {
			return err
		}

		ok := cu.strat.OnExecuteDone(exRes)
		if !ok {
			fmt.Println("Program produced unexpected results")
			ebpf.GeneratePoc(prog, 0)
		}
	}
	return nil
}
