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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/escaping.h"
#include "google/protobuf/message.h"
#include "google/protobuf/repeated_field.h"
#include "proto/ffi.pb.h"

#define KCOV_INIT_TRACE _IOR('c', 1, uint64_t)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

#define KCOV_TRACE_PC 0
#define KCOV_TRACE_CMP 1

// 64mb for kcov coverage.
#define KCOV_SIZE 1024 * 1024 * 64

using ebpf_fuzzer::CbpfExecutionRequest;
using ebpf_fuzzer::EncodedProgram;
using ebpf_fuzzer::ExecutionRequest;
using ebpf_fuzzer::ExecutionResult;
using ebpf_fuzzer::MapElements;
using ebpf_fuzzer::ValidationResult;

// All the functions in this extern are FFIs intended to be invoked from go.
extern "C" {
// This struct is used to return the serialized proto containing the verify
// results.
struct bpf_result {
  char *serialized_proto;
  size_t size;
};

bpf_result serialize_proto(const google::protobuf::Message &proto);

bool execute_error(std::string &error_message, const char *strerr,
                   int *sockets);

struct bpf_result return_error(std::string error_message,
                               ExecutionResult *result);

// Creates an ebpf map, returns the file descriptor to it.
int ffi_create_bpf_map(size_t size);

// Closes the given file descriptor, this is to free up resources.
void ffi_close_fd(int fd);

// Enable kcov coverage.
int ffi_setup_coverage();

// Disble kcov coverage.
int ffi_cleanup_coverage();

bool enable_coverage();
void disable_coverage();
void get_coverage(ValidationResult *vres);

struct coverage_data {
  int fd;
  uint64_t coverage_size;
  uint64_t *coverage_buffer;
};

extern struct coverage_data* kCoverageData;
}

#endif  // EBPF_FUZZER_EBPF_FFI_FFI_H_
