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

// Package playground is meant to be a strategy where different functionalities
// of ebpf can be tested more easily, it's purpose is to experiment more so than
// fuzz.
package stackcorruption

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
	StrategyName = "stack_corruption"
)

// Strategy implements the playground strategy.
type Strategy struct {
	mapSize int
}

// Fuzz implements the main fuzzing logic.
func (sc *Strategy) Fuzz(e strategies.ExecutorInterface, cm strategies.CoverageManager) error {
	sc.mapSize = 3
	fmt.Printf("running fuzzing strategy %s\n", StrategyName)
	count := 0
	valid := 0
	invalid := 0
	bugs := 0
	for true {
		fmt.Printf("count: %d, valid: %d, invalid: %d, bugs: %d                                              \r", count, valid, invalid, bugs)
		count += 1
		gen := &Generator{
			magicNumber: 0xCAFE,
		}
		prog, err := ebpf.New(sc.mapSize, ebpf.RegR6.RegisterNumber(), ebpf.RegR9.RegisterNumber())
		prog.Instructions = gen.Generate(prog)

		if err != nil {
			fmt.Println(err)
			prog.Cleanup()
			continue
		}
		byteCode := prog.GenerateBytecode()
		res, err := e.ValidateProgram(byteCode)
		gr := &strategies.GeneratorResult{
			Prog:         prog,
			ProgByteCode: byteCode,
			ProgFD:       res.GetProgramFd(),
			VerifierLog:  res.GetVerifierLog(),
		}
		if err != nil {
			fmt.Println(err)
			prog.Cleanup()
			continue
		}

		if !res.GetIsValid() {
			invalid += 1
			prog.Cleanup()
			continue
		}

		valid += 1

		mapDescription := &fpb.ExecutionRequest_MapDescription{
			MapFd:   int64(prog.LogMap()),
			MapSize: uint64(sc.mapSize),
		}
		executionRequest := &fpb.ExecutionRequest{
			ProgFd: res.GetProgramFd(),
			Maps:   []*fpb.ExecutionRequest_MapDescription{mapDescription},
			InputData: []byte{0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		}

		executionResponse, err := e.RunProgram(executionRequest)
		if err != nil {
			fmt.Println(err)
		}

		mapElements := executionResponse.GetMapElements()[0].GetElements()

		if mapElements[0] != mapElements[1] {
			fmt.Println()
			fmt.Printf("program wrote out of bounds")
			strategies.SaveExecutionResults(gr)
			prog.GeneratePoc()
			bugs += 1
			prog.Cleanup()
			continue
		} else if mapElements[2] == 0 {
			fmt.Println()
			fmt.Printf("skb read failed but program was not rejected")
			strategies.SaveExecutionResults(gr)
			prog.GeneratePoc()
			bugs += 1
			prog.Cleanup()
			continue
		}

		prog.Cleanup()
		C.close_fd(C.int(executionRequest.GetProgFd()))
	}
	return nil
}
