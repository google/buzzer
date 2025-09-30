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

#ifndef EBPF_FUZZER_EBPF_FFI_EBPF_H_
#define EBPF_FUZZER_EBPF_FFI_EBPF_H_

#include <linux/bpf.h>

#include <cstdint>
#include <string>
#include <vector>

#include "ebpf_ffi/ffi.h"

extern "C" {

// Actual implementation of load program. The split between ffi and
// implementation is done so the impl code can be shared with other parts of the
// codebase also written in C++.
ValidationResult load_ebpf_program(EncodedProgram program, std::string &error);

// Loads a bpf program specified by |prog_buff| with |size| and returns struct
// with a serialized ValidationResult proto.
struct bpf_result ffi_load_ebpf_program(void *serialized_proto, size_t size,
                                        int coverage_enabled,
                                        uint64_t coverage_size);

bool get_map_elements(int map_fd, size_t map_size, std::vector<uint64_t> *res,
                      std::string &error);

// Sets the value at key |key| in the map described by |map_fd| to |value|.
int ffi_update_map_element(int map_fd, int key, uint64_t value);

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
                   unsigned int value_size, unsigned int max_entries);

// Creates an ebpf map, returns the file descriptor to it.
int ffi_create_bpf_map(size_t size);

// Retrieves the elements of the specified map_fd, return value is of type
// MapElements.
struct bpf_result ffi_get_map_elements(int map_fd, uint64_t map_size);

bool execute_ebpf_program(int prog_fd, uint8_t *input, int input_length,
                          std::string &error_message);

/// Runs the specified ebpf program by sending some data to a socket.
// Serialized proto is of type ExecutionRequest.
struct bpf_result ffi_execute_ebpf_program(void *serialized_proto,
                                           size_t length);

// Helps clean up any setup map fd array for a program.
void ffi_clean_fd_array(unsigned long long int addr, int size);
}
#endif  // EBPF_FUZZER_EBPF_FFI_EBPF_H_
