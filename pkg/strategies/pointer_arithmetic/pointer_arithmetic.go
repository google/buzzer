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
		prog, err := ebpf.New( /*mapSize=*/ 4 /*minReg=*/, ebpf.RegR0.RegisterNumber() /*maxReg=*/, ebpf.RegR9.RegisterNumber())
		prog.Instructions = gen.Generate(prog)
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

func (pa *Strategy) executeProgram(e strategies.ExecutorInterface, executionRequest *fpb.ExecutionRequest) (*fpb.ExecutionResult, error) {
	eR, err := e.RunProgram(executionRequest)
	if err != nil {
		return nil, err
	}

	if !eR.GetDidSucceed() {
		return nil, fmt.Errorf("execute Program did not succeed")
	}
	return eR, nil
}

// Fuzz implements the main fuzzing logic.
func (pa *Strategy) Fuzz(e strategies.ExecutorInterface, cm strategies.CoverageManager) error {
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
		mapDescription := &fpb.ExecutionRequest_MapDescription{
			MapFd:   int64(gr.Prog.LogMap()),
			MapSize: uint64(2),
		}
		executionRequest := &fpb.ExecutionRequest{
			ProgFd: gr.ProgFD,
			Maps:   []*fpb.ExecutionRequest_MapDescription{mapDescription},
		}

		if err := func() error {
			defer func() {
				C.close_fd(C.int(executionRequest.GetProgFd()))
				C.close_fd(C.int(mapDescription.GetMapFd()))
			}()
			exRes, err := pa.executeProgram(e, executionRequest)

			if err != nil {
				return err
			}

			// Given that we write the magic number twice, one with pointer
			// arithmetic and another one without it, we expect the first
			// two elements to be the same. Otherwise, we wrote out of
			// bounds.
			if len(exRes.GetMapElements()) != 0 {
				mapElements := exRes.GetMapElements()[0].GetElements()
				if mapElements[0] != mapElements[1] {
					strategies.SaveExecutionResults(gr)
					return fmt.Errorf("Program wrote out of bounds")
				}
			}
			return nil
		}(); err != nil {
			return err
		}
	}
}
