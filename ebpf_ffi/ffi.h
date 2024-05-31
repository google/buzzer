/*
 * Copyright 2023 Google LLC
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

#ifndef EBPF_FUZZER_EBPF_FFI_FFI_H_
#define EBPF_FUZZER_EBPF_FFI_FFI_H_

#include <linux/bpf.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// All the functions in this extern are FFIs intended to be invoked from go.
extern "C" {
// This struct is used to return the serialized proto containing the verify
// results.
struct bpf_result {
  char *serialized_proto;
  size_t size;
};

// Loads a bpf program specified by |prog_buff| with |size| and returns struct
// with a serialized ValidationResult proto.
struct bpf_result ffi_load_bpf_program(void *prog_buff, size_t size,
                                       int coverage_enabled,
                                       uint64_t coverage_size);

// Creates an ebpf map, returns the file descriptor to it.
int ffi_create_bpf_map(size_t size);

// Closes the given file descriptor, this is to free up resources.
void ffi_close_fd(int fd);

// Runs the specified ebpf program by sending some data to a socket.
// Serialized proto is of type ExecutionRequest.
struct bpf_result ffi_execute_bpf_program(void *serialized_proto,
                                          size_t length);

// Retrieves the elements of the specified map_fd, return value is of type
// MapElements.
struct bpf_result ffi_get_map_elements(int map_fd, uint64_t map_size);

// Sets the value at key |key| in the map described by |map_fd| to |value|.
int ffi_update_map_element(int map_fd, int key, uint64_t value);
}

// Actual implementation of load program. The split between ffi and
// implementation is done so the impl code can be shared with other parts of the
// codebase also written in C++.
int load_bpf_program(void *prog_buff, size_t prog_size,
                     std::string *verifier_log, std::string *error);
bool get_map_elements(int map_fd, size_t map_size, std::vector<uint64_t> *res,
                      std::string *error);
int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
                   unsigned int value_size, unsigned int max_entries);
bool execute_bpf_program(int prog_fd, uint8_t *input, int input_length,
                         std::string *error_message);

struct coverage_data {
  int fd;
  uint64_t coverage_size;
  uint64_t *coverage_buffer;
};
#endif  // EBPF_FUZZER_EBPF_FFI_FFI_H_
