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
//#include <stdint.h>
//#include <stdlib.h>
//struct bpf_result {
//  char* serialized_proto;
//  size_t size;
//};
//struct bpf_result ffi_load_cbpf_program(void* prog_buff, size_t size);
//struct bpf_result ffi_execute_cbpf_program(void* serialized_proto, size_t length);
//struct bpf_result ffi_load_ebpf_program(void* serialized_proto, size_t size);
//struct bpf_result ffi_execute_ebpf_program(void* serialized_proto, size_t length);
//struct bpf_result ffi_get_map_elements(int map_fd, uint64_t map_size);
//struct bpf_result ffi_get_map_elements_fd_array(uint64_t fd_array_addr, uint32_t idx, uint64_t map_size);
//int ffi_create_bpf_map(size_t size);
//void ffi_close_fd(int fd);
//int ffi_update_map_element(int map_fd, int key, uint64_t value);
//void ffi_clean_fd_array(unsigned long long int addr, int size);
//int ffi_setup_coverage();
//int ffi_cleanup_coverage();
import "C"

import (
	"buzzer/pkg/cbpf/cbpf"
	fpb "buzzer/proto/ffi_go_proto"
	"encoding/base64"
	"fmt"
	"github.com/golang/protobuf/proto"
	"unsafe"
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

func mapElementsProtoFromStruct(s *C.struct_bpf_result) (*fpb.MapElements, error) {
	data, err := protoDataFromStruct(s)

	if err != nil {
		return nil, err
	}

	res := &fpb.MapElements{}
	if err := proto.Unmarshal(data, res); err != nil {
		return nil, err
	}

	return res, nil
}

// FFI is the unit that will talk to ebpf and run/validate programs.
type FFI struct {
	MetricsUnit *Metrics
}

// CreateMapArray creates an ebpf map of type array and returns its fd.
// -1 means error.
func (e *FFI) CreateMapArray(size uint64) int {
	return int(C.ffi_create_bpf_map(C.ulong(size)))
}

// CloseFD closes the provided file descriptor.
func (e *FFI) CloseFD(fd int) {
	C.ffi_close_fd(C.int(fd))
}

// GetMapElements fetches the map elements of the given fd.
func (e *FFI) GetMapElements(fd int, mapSize uint64) (*fpb.MapElements, error) {
	res := C.ffi_get_map_elements(C.int(fd), C.ulong(mapSize))
	return mapElementsProtoFromStruct(&res)
}

// GetMapElements fetches the map elements of the given fd_array position.
func (e *FFI) GetMapElementsFdArray(fd_array uint64, idx uint32, mapSize uint32) (*fpb.MapElements, error) {
	res := C.ffi_get_map_elements_fd_array(C.ulong(fd_array), C.uint(idx), C.ulong(mapSize))
	return mapElementsProtoFromStruct(&res)
}

// SetMapElement sets the elemnt specified by `key` to `value` in the map
// described by `fd`
func (e *FFI) SetMapElement(fd int, key uint32, value uint64) int {
	return int(C.ffi_update_map_element(C.int(fd), C.int(key), C.ulong(value)))
}

// SetMapElement sets the elemnt specified by `key` to `value` in the map
// described by `fd`
func (e *FFI) CleanFdArray(fd_array uint64, size int) {
	if fd_array == 0 {
		return
	}
	C.ffi_clean_fd_array(C.ulonglong(fd_array), C.int(size))
}

// ----------- eBPF --------------
// ValidateProgram passes the program through the bpf verifier without executing
// it. Returns feedback to the generator so it can adjust the generation
// settings.
func (e *FFI) ValidateEbpfProgram(encodedProgram *fpb.EncodedProgram) (*fpb.ValidationResult, error) {
	if len(encodedProgram.Program) == 0 && encodedProgram != nil {
		return nil, fmt.Errorf("cannot run empty program")
	}
	serializedProto, err := proto.Marshal(encodedProgram)
	bpfVerifyResult := C.ffi_load_ebpf_program(unsafe.Pointer(&serializedProto[0]), C.ulong(len(serializedProto)))
	res, err := validationProtoFromStruct(&bpfVerifyResult)
	if err != nil {
		return nil, err
	}
	e.MetricsUnit.RecordVerificationResults(res)
	return res, nil
}

// RunProgram Runs the ebpf program and returns the execution results.
func (e *FFI) RunEbpfProgram(executionRequest *fpb.ExecutionRequest) (*fpb.ExecutionResult, error) {
	serializedProto, err := proto.Marshal(executionRequest)
	if err != nil {
		return nil, err
	}
	res := C.ffi_execute_ebpf_program(unsafe.Pointer(&serializedProto[0]), C.ulong(len(serializedProto)))
	return executionProtoFromStruct(&res)
}

// ---------- cBPF --------------
// ValidateProgram passes the program through the bpf verifier without executing
// it. Returns feedback to the generator so it can adjust the generation
// settings.
func (e *FFI) ValidateCbpfProgram(prog []cbpf.Filter) (*fpb.ValidationResult, error) {
	if len(prog) == 0 {
		return nil, fmt.Errorf("cannot run empty program")
	}
	bpfVerifyResult := C.ffi_load_cbpf_program(unsafe.Pointer(&prog[0]), C.ulong(len(prog)))
	res, err := validationProtoFromStruct(&bpfVerifyResult)
	if err != nil {
		return nil, err
	}
	e.MetricsUnit.RecordVerificationResults(res)
	return res, nil
}

// RunProgram Runs the cbpf program and returns the execution results.
func (e *FFI) RunCbpfProgram(executionRequest *fpb.CbpfExecutionRequest) (*fpb.ExecutionResult, error) {
	serializedProto, err := proto.Marshal(executionRequest)
	if err != nil {
		return nil, err
	}
	res := C.ffi_execute_cbpf_program(unsafe.Pointer(&serializedProto[0]), C.ulong(len(serializedProto)))
	return executionProtoFromStruct(&res)
}

// InitKcov sets up all the required kcov structures.
func (e *FFI) InitKcov() {
	if C.ffi_setup_coverage() != 0 {
		fmt.Println("could not setup coverage correctly")
	}
}

// CleanupKcov destroys all the resources created for kcov.
func (e *FFI) CleanupKcov() {
	C.ffi_cleanup_coverage()
}
