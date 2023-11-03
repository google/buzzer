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

// Package parseverifier implements a strategy of generating random
// ALU operations and then attempting to hunt verifier logic errors by parsing
// the output of the vierifier log and comparing the values the verifier thinks
// the registers will have vs the actual values that are observed at run time.
package parseverifier

//#include <stdlib.h>
//void close_fd(int fd);
import "C"

import (
	"errors"
	"fmt"

	"buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/strategies/parse_verifier/oracle/oracle"
	"buzzer/pkg/strategies/strategies"
	fpb "buzzer/proto/ebpf_fuzzer_go_proto"
)

const (
	// StrategyName exposes the value of the flag that should be used to
	// invoke this strategy.
	StrategyName = "parse_verifier_log"
)

// StrategyParseVerifierLog Implements a fuzzing strategy where the results of
// the ebpf verifier will be parsed and then compared with the actual values
// observed at run time.
type StrategyParseVerifierLog struct{}

func (st *StrategyParseVerifierLog) generateAndValidateProgram(e strategies.ExecutorInterface, gen *Generator) (*strategies.GeneratorResult, error) {
	for i := 0; i < 100_000; i++ {
		prog, err := ebpf.New(gen /*mapSize=*/, 1000 /*minReg=*/, ebpf.RegR7.RegisterNumber() /*maxReg=*/, ebpf.RegR9.RegisterNumber())
		if err != nil {
			return nil, err
		}
		byteCode := prog.GenerateBytecode()
		res, err := e.ValidateProgram(byteCode)
		if err != nil {
			prog.Cleanup()
			return nil, err
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
	return nil, errors.New("could not generate a valid program")
}

// Fuzz implements the main fuzzing logic.
func (st *StrategyParseVerifierLog) Fuzz(e strategies.ExecutorInterface, cm strategies.CoverageManager) error {
	fmt.Printf("running fuzzing strategy %s\n", StrategyName)
	i := 0
	for {
		gen := &Generator{
			instructionCount: 10,
			offsetMap:        make(map[int32]int32),
			sizeMap:          make(map[int32]int32),
			regMap:           make(map[int32]uint8),
		}
		fmt.Printf("Fuzzer run no %d.                               \r", i)
		i++
		gr, err := st.generateAndValidateProgram(e, gen)

		if err != nil {
			return err
		}

		// Build a new execution request.
		logMap := gr.Prog.LogMap()
		logCount := gen.logCount
		mapDescription := &fpb.ExecutionRequest_MapDescription{
			MapFd:   int64(logMap),
			MapSize: uint64(logCount),
		}
		executionRequest := &fpb.ExecutionRequest{
			ProgFd: gr.ProgFD,
			Maps:   []*fpb.ExecutionRequest_MapDescription{mapDescription},
		}

		defer func() {
			C.close_fd(C.int(executionRequest.GetProgFd()))
			C.close_fd(C.int(mapDescription.GetMapFd()))
		}()

		programFlaked := true

		var exRes *fpb.ExecutionResult
		maxAttempts := 1000

		for programFlaked && maxAttempts != 0 {
			maxAttempts--
			eR, err := e.RunProgram(executionRequest)
			if err != nil {
				return err
			}

			if !eR.GetDidSucceed() {
				return fmt.Errorf("execute Program did not succeed")
			}
			mapElements := eR.GetMapElements()[0].GetElements()
			for i := 0; i < len(mapElements); i++ {
				if mapElements[i] != 0 {
					programFlaked = false
					exRes = eR
					break
				}
			}
		}

		if maxAttempts == 0 {
			fmt.Println("program flaked")
			strategies.SaveExecutionResults(gr)
			continue
		}

		// Program succeeded, let's validate the execution map.
		regOracle, err := oracle.FromVerifierTrace(gr.VerifierLog)
		if err != nil {
			return err
		}

		mapSize := int32(executionRequest.GetMaps()[0].GetMapSize())
		mapElements := exRes.GetMapElements()[0].GetElements()
		for mapIndex := int32(0); mapIndex < mapSize; mapIndex++ {
			offset := gen.GetProgramOffset(mapIndex)
			dstReg := gen.GetDestReg(mapIndex)
			verifierValue, known, err := regOracle.LookupRegValue(offset, dstReg)
			if err != nil {
				return err
			}
			actualValue := mapElements[mapIndex]
			if known && verifierValue != actualValue {
				if err := strategies.SaveExecutionResults(gr); err != nil {
					return err
				}
			}
		}

		C.close_fd(C.int(executionRequest.GetProgFd()))
		C.close_fd(C.int(mapDescription.GetMapFd()))
	}
	return nil
}
