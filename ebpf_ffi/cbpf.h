/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef EBPF_FUZZER_EBPF_FFI_CBPF_H_
#define EBPF_FUZZER_EBPF_FFI_CBPF_H_

#include "ffi.h"

extern "C" {

// Actual implementation of load program. The split between ffi and
// implementation is done so the impl code can be shared with other parts of the
// codebase also written in C++.
int *load_cbpf_program(void *prog_buff, std::string *error);

// Loads a bpf program specified by |prog_buff| with |size| and returns struct
// with a serialized ValidationResult proto.
struct bpf_result ffi_load_cbpf_program(void *prog_buff, int coverage_enabled,
                                        uint64_t coverage_size);

bool execute_cbpf_program(int prog_fd, uint8_t *input, int input_length,
                          std::string *error_message);

// Runs the specified ebpf program by sending some data to a socket.
// Serialized proto is of type ExecutionRequest.
struct bpf_result ffi_execute_cbpf_program(void *serialized_proto,
                                           size_t length);
}
#endif  // EBPF_FUZZER_EBPF_FFI_CBPF_H_
