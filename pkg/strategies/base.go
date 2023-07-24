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

// Package strategies contains the base that all strategies need to be
// implemented, this is defined in order to prevent repetition of code among
// strategies.
package strategies

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"buzzer/pkg/ebpf/ebpf"
	fpb "buzzer/proto/ebpf_fuzzer_go_proto"
)

// GeneratorResult holds the state of generated programs that have been verified.
type GeneratorResult struct {
	Prog         *ebpf.Program
	ProgFD       int64
	ProgByteCode []uint64
	VerifierLog  string
}

// ExecutorInterface is defined for mocking purposes.
type ExecutorInterface interface {
	ValidateProgram(prog []uint64) (*fpb.ValidationResult, error)
	RunProgram(rpr *fpb.ExecutionRequest) (*fpb.ExecutionResult, error)
}

// WriteLogFile writes the verifier log `data` to a temporary file.
func WriteLogFile(data []byte) error {
	f, err := os.CreateTemp("", "verifier-log-")
	if err != nil {
		return err
	}

	fmt.Printf("Writing verifier log to %q.\n", f.Name())
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// WriteProgFile writes the `data` representing an ebpf program to a
// temporary file.
func WriteProgFile(data []uint64) error {
	f, err := os.CreateTemp("", "ebpf-binary-")
	if err != nil {
		return err
	}

	fmt.Printf("Writing eBPF binary to %q.\n", f.Name())

	out := []byte{}
	b := make([]byte, 8)
	for _, value := range data {
		binary.LittleEndian.PutUint64(b, value)
		out = append(out, b...)
	}

	_, err = f.Write(out)

	return errors.Join(err, f.Close())
}

// SaveExecutionResults saves the verifier log and ebpf binary program to
// a tmp file for further dissection.
func SaveExecutionResults(gr *GeneratorResult) error {
	if err := WriteLogFile([]byte(gr.VerifierLog)); err != nil {
		return err
	}
	return WriteProgFile(gr.ProgByteCode)
}
