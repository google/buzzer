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

extern "C" {
// This struct is used to return the serialized proto containing the verify
// results.
struct bpf_result {
  char *serialized_proto;
  size_t size;
};

// Loads a bpf program specified by |prog_buff| with |size| and returns struct
// with a serialized ValidationResult proto.
struct bpf_result load_bpf_program(void *prog_buff, size_t size,
                                   int coverage_enabled,
                                   uint64_t coverage_size);

// Creates an ebpf map, returns the file descriptor to it.
int create_bpf_map(size_t size);

// Closes the given file descriptor, this is to free up resources.
void close_fd(int fd);

// Runs the specified ebpf program by sending some data to a socket.
// Serialized proto is of type ExecutionRequest.
struct bpf_result execute_bpf_program(void *serialized_proto, size_t length);


// Retrieves the elements of the specified map_fd, return value is of type
// MapElements.
struct bpf_result get_map_elements(int map_fd, uint64_t map_size);
}

struct coverage_data {
  int fd;
  uint64_t coverage_size;
  uint64_t *coverage_buffer;
};
#endif  // EBPF_FUZZER_EBPF_FFI_FFI_H_
