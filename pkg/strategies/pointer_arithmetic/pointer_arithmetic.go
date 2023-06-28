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

// Package pointerarithmetic implements a strategy of generating random
// ALU operations and then performing pointer arithmetic with a map pointer
// and attempting to write to that pointer. Then check if the value was actually
// written to the map or not.
package pointerarithmetic

//#include <stdlib.h>
//void close_fd(int fd);
import "C"

import (
	"fmt"

	"buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/strategies/strategies"
	fpb "buzzer/proto/ebpf_fuzzer_go_proto"
)

const (
	// StrategyName exposes the value of the flag that should be used to
	// invoke this strategy.
	StrategyName = "pointer_arithmetic"
)

// Strategy Implements a fuzzing strategy where the results of
// the ebpf verifier will be parsed and then compared with the actual values
// observed at run time.
type Strategy struct {
	InstructionCount int
}

func (pa *Strategy) generateAndValidateProgram(e strategies.ExecutorInterface, gen *Generator) (*strategies.GeneratorResult, error) {
	for i := 0; ; i++ {
		gen.instructionCount = pa.InstructionCount
		prog, err := ebpf.New(gen /*mapSize=*/, 4 /*minReg=*/, ebpf.RegR6.RegisterNumber() /*maxReg=*/, ebpf.RegR9.RegisterNumber())
		if err != nil {
			return nil, err
		}
		byteCode := prog.GenerateBytecode()
		res, err := e.ValidateProgram(byteCode)
		if err != nil {
			prog.Cleanup()
			return nil, err
		}

		// Only print every 2000 generated programs.
		if i%2000 == 0 {
			fmt.Println(res.GetVerifierLog())
		}

		if res.GetIsValid() {
			result := &strategies.GeneratorResult{
				Prog:         prog,
				ProgByteCode: byteCode,
				ProgFD:       res.GetProgramFd(),
				VerifierLog:  res.GetVerifierLog(),
			}

			return result, nil
		}
		prog.Cleanup()
	}
}

func (pa *Strategy) executeProgram(e strategies.ExecutorInterface, rpr *fpb.RunProgramRequest) (*fpb.ExecutionResult, error) {
	programFlaked := true

	var exRes *fpb.ExecutionResult
	maxAttempts := 1000

	for programFlaked && maxAttempts != 0 {
		maxAttempts--
		eR, err := e.RunProgram(rpr)
		if err != nil {
			return nil, err
		}

		if !eR.GetDidSucceed() {
			return nil, fmt.Errorf("execute Program did not succeed")
		}
		for i := 0; i < len(eR.GetElements()); i++ {
			if eR.GetElements()[i] != 0 {
				programFlaked = false
				exRes = eR
				break
			}
		}
	}

	if maxAttempts == 0 {
		return nil, fmt.Errorf("program flaked a lot")
	}

	return exRes, nil
}

// Fuzz implements the main fuzzing logic.
func (pa *Strategy) Fuzz(e strategies.ExecutorInterface) error {
	fmt.Printf("running fuzzing strategy %s\n", StrategyName)
	i := 0
	for {
		gen := &Generator{
			instructionCount: pa.InstructionCount,
			magicNumber:      0xCAFE,
		}
		fmt.Printf("Fuzzer run no %d.                               \r", i)
		i++
		gr, err := pa.generateAndValidateProgram(e, gen)

		if err != nil {
			return err
		}

		// Build a new execution request.
		logMap := gr.Prog.LogMap()
		rpr := &fpb.RunProgramRequest{
			ProgFd:      gr.ProgFD,
			MapFd:       int64(logMap),
			MapCount:    2,
			EbpfProgram: gr.ProgByteCode,
		}

		if err := func() error {
			defer func() {
				C.close_fd(C.int(rpr.GetProgFd()))
				C.close_fd(C.int(rpr.GetMapFd()))
			}()
			exRes, err := pa.executeProgram(e, rpr)

			if err != nil {
				return err
			}

			// Given that we write the magic number twice, one with pointer
			// arithmetic and another one without it, we expect the first
			// two elements to be the same. Otherwise, we wrote out of
			// bounds.
			if exRes.GetElements()[0] != exRes.GetElements()[1] {
				strategies.SaveExecutionResults(gr)
				return fmt.Errorf("Program wrote out of bounds")
			}
			return nil
		}(); err != nil {
			return err
		}
	}
}
