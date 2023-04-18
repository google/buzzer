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

package units

//#include <linux/bpf.h>
//#include <stdlib.h>
//struct bpf_result {
//  char* serialized_proto;
//  size_t size;
//};
//struct bpf_result load_bpf_program(void* prog_buff, size_t size, int coverage_enabled, unsigned long coverage_size);
//struct bpf_result execute_bpf_program(int prog_fd, int map_fd, int map_count);
import "C"

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	fpb "buzzer/proto/ebpf_fuzzer_go_proto"
	"buzzer/pkg/metrics/metrics"
	"github.com/golang/protobuf/proto"
)

// Takes the results returned by the c FFI and reconstructs the result proto.
// This will release the memory allocated by the c ffi and set the pointer in
// the struct to null so it doesn't get reused.
func protoDataFromStruct(s *C.struct_bpf_result) ([]byte, error) {
	if s.serialized_proto == nil {
		return nil, fmt.Errorf("serialized proto is nil")
	}
	defer func() {
		C.free(unsafe.Pointer(s.serialized_proto))
		s.serialized_proto = nil
	}()
	pb64 := C.GoStringN(s.serialized_proto, C.int(s.size))
	data, err := base64.StdEncoding.DecodeString(pb64)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func validationProtoFromStruct(s *C.struct_bpf_result) (*fpb.ValidationResult, error) {
	data, err := protoDataFromStruct(s)

	if err != nil {
		return nil, err
	}

	res := &fpb.ValidationResult{}
	if err := proto.Unmarshal(data, res); err != nil {
		return nil, err
	}

	return res, nil
}

func executionProtoFromStruct(s *C.struct_bpf_result) (*fpb.ExecutionResult, error) {
	data, err := protoDataFromStruct(s)

	if err != nil {
		return nil, err
	}

	res := &fpb.ExecutionResult{}
	if err := proto.Unmarshal(data, res); err != nil {
		return nil, err
	}

	return res, nil
}

// Executor is the unit that will talk to ebpf and run/validate programs.
type Executor struct {
	MetricsUnit *metrics.CentralUnit
}

// ValidateProgram passes the program through the bpf verifier without executing
// it. Returns feedback to the generator so it can adjust the generation
// settings.
func (e *Executor) ValidateProgram(prog []uint64) (*fpb.ValidationResult, error) {
	if len(prog) == 0 {
		return nil, fmt.Errorf("cannot run empty program")
	}
	shouldCollect, coverageSize := e.MetricsUnit.ShouldGetCoverage()
	cbool := 0
	if shouldCollect {
		cbool = 1
	}
	bpfVerifyResult := C.load_bpf_program(unsafe.Pointer(&prog[0]), C.ulong(len(prog)) /*enable_coverage=*/, C.int(cbool) /*coverage_size=*/, C.ulong(coverageSize))
	res, err := validationProtoFromStruct(&bpfVerifyResult)
	if err != nil {
		return nil, err
	}
	e.MetricsUnit.RecordVerificationResults(res)
	return res, nil
}

// RunProgram Runs the ebpf program and returns the execution results.
func (e *Executor) RunProgram(runProgramRequest *fpb.RunProgramRequest) (*fpb.ExecutionResult, error) {
	res := C.execute_bpf_program(C.int(runProgramRequest.GetProgFd()), C.int(runProgramRequest.GetMapFd()), C.int(runProgramRequest.GetMapCount()))
	exRes, err := executionProtoFromStruct(&res)
	if err != nil {
		return nil, err
	}
	if !exRes.GetDidSucceed() {
		return nil, fmt.Errorf("Run program did not succeed")
	}
	return exRes, nil
}
