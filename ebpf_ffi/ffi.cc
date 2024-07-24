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

#include "ebpf_ffi/ffi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>
#include <unordered_set>

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

using ebpf_fuzzer::ExecutionRequest;
using ebpf_fuzzer::ExecutionResult;
using ebpf_fuzzer::MapElements;
using ebpf_fuzzer::ValidationResult;

// All the functions in this extern are FFIs intended to be invoked from go.
extern "C" {

bpf_result serialize_proto(const google::protobuf::Message &proto) {
  std::string proto_encoded;
  absl::Base64Escape(proto.SerializeAsString(), &proto_encoded);

  // The memory for this string will be freed by the Go program.
  char *serialized_proto =
      reinterpret_cast<char *>(malloc(proto_encoded.size() + 1));
  strncpy(serialized_proto, proto_encoded.c_str(), proto_encoded.size());

  struct bpf_result res;
  res.serialized_proto = serialized_proto;
  res.size = proto_encoded.size();
  return res;
}

void enable_coverage(struct coverage_data *coverage_info) {
  int fd = open("/sys/kernel/debug/kcov", O_RDWR);
  if (fd == -1) return;
  /* Setup trace mode and trace size. */
  if (ioctl(fd, KCOV_INIT_TRACE, coverage_info->coverage_size)) return;
  /* Mmap buffer shared between kernel- and user-space. */
  uint64_t *cover =
      (uint64_t *)mmap(nullptr, coverage_info->coverage_size * sizeof(uint64_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if ((void *)cover == MAP_FAILED) return;
  /* Enable coverage collection on the current thread. */
  if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)) return;
  /* Reset coverage from the tail of the ioctl() call. */
  __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
  coverage_info->fd = fd;
  coverage_info->coverage_buffer = cover;
}

void get_coverage_and_free_resources(struct coverage_data *cstruct,
                                     ValidationResult *vres) {
  if (cstruct->fd == -1) return;
  uint64_t trace_size =
      __atomic_load_n(&cstruct->coverage_buffer[0], __ATOMIC_RELAXED);

  auto *coverage_addresses = vres->mutable_coverage_address();
  absl::flat_hash_set<uint64_t> seen_address;
  for (uint64_t i = 0; i < trace_size; i++) {
    uint64_t addr = cstruct->coverage_buffer[i + 1];
    if (seen_address.find(addr) == seen_address.end()) {
      coverage_addresses->Add(cstruct->coverage_buffer[i + 1]);
      seen_address.insert(addr);
    }
  }

  ioctl(cstruct->fd, KCOV_DISABLE, 0);
  close(cstruct->fd);
  munmap(cstruct->coverage_buffer, cstruct->coverage_size * sizeof(uint64_t));
}

bool execute_error(std::string& error_message, const char *strerr,
                   int *sockets) {
  if (sockets != nullptr) {
    close(sockets[0]);
    close(sockets[1]);
  }
  error_message = strerr;
  return false;
}

struct bpf_result return_error(std::string error_message,
                               ExecutionResult *result) {
  result->set_did_succeed(false);
  result->set_error_message(error_message);
  return serialize_proto(*result);
}

void ffi_close_fd(int prog_fd) { close(prog_fd); }
}
