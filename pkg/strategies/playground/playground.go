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
package playground

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
	StrategyName = "playground"
)

// Strategy implements the playground strategy.
type Strategy struct {
	mapSize int
}

// Fuzz implements the main fuzzing logic.
func (pg *Strategy) Fuzz(e strategies.ExecutorInterface, cm strategies.CoverageManager) error {
	// 4 is an arbitrary number.
	pg.mapSize = 4
	fmt.Printf("running fuzzing strategy %s\n", StrategyName)
	gen := &Generator{}
	prog, err := ebpf.New(gen, pg.mapSize, ebpf.RegR0.RegisterNumber(), ebpf.RegR9.RegisterNumber())

	if prog != nil {
		defer func() {
			prog.Cleanup()
		}()
	}

	if err != nil {
		return err
	}
	byteCode := prog.GenerateBytecode()
	res, err := e.ValidateProgram(byteCode)
	if err != nil {
		return err
	}

	fmt.Println("Verifier Log:")
	fmt.Println(res.GetVerifierLog())

	if !res.GetIsValid() {
		return fmt.Errorf("generated invalid program")
	}

	mapDescriptor := &fpb.ExecutionRequest_MapDescription{
		MapFd:   int64(prog.LogMap()),
		MapSize: uint64(pg.mapSize),
	}

	executionRequest := &fpb.ExecutionRequest{
		ProgFd: res.GetProgramFd(),
		Maps:   []*fpb.ExecutionRequest_MapDescription{mapDescriptor},
	}

	defer func() {
		C.close_fd(C.int(executionRequest.GetProgFd()))
		C.close_fd(C.int(mapDescriptor.GetMapSize()))
	}()

	_, err = e.RunProgram(executionRequest)
	if err != nil {
		return err
	}
	err = prog.GeneratePoc()
	if err != nil {
		fmt.Printf("could not generate poc %v", err)
		return err
	}
	return nil
}
