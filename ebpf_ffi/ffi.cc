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

namespace ebpf_ffi {

// This constant was determined arbitrarily, the number of 0's has incremented
// when the size was no longer enough for the verifier logs.
constexpr size_t kLogBuffSize = 100000000;
}  // namespace ebpf_ffi

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
  if (!trace_size) {
    int *a = NULL;
    *a = 1337;
  }

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

struct bpf_result ffi_load_bpf_program(void *prog_buff, size_t size,
                                       int coverage_enabled,
                                       uint64_t coverage_size) {
  std::string verifier_log, error_message;
  struct coverage_data cover;
  memset(&cover, 0, sizeof(struct coverage_data));
  cover.fd = -1;
  cover.coverage_size = coverage_size;
  if (coverage_enabled) enable_coverage(&cover);

  int program_fd =
      load_bpf_program(prog_buff, size, &verifier_log, &error_message);

  ValidationResult vres;
  if (coverage_enabled) get_coverage_and_free_resources(&cover, &vres);

  // Start building the validation result proto.
  vres.set_verifier_log(verifier_log);
  vres.set_program_fd(program_fd);

  if (cover.fd != -1) {
    vres.set_did_collect_coverage(true);
    vres.set_coverage_size(cover.coverage_size);
    vres.set_coverage_buffer(reinterpret_cast<uint64_t>(cover.coverage_buffer));
  } else {
    vres.set_did_collect_coverage(false);
  }

  if (program_fd < 0) {
    // Return why we failed to load the program.
    vres.set_bpf_error(error_message);
    vres.set_is_valid(false);
  } else {
    vres.set_is_valid(true);
  }

  return serialize_proto(vres);
}

int load_bpf_program(void *prog_buff, size_t prog_size,
                     std::string *verifier_log, std::string *error) {
  struct bpf_insn *insn;
  union bpf_attr attr = {};

  // For the verifier log.
  unsigned char *log_buf = (unsigned char *)malloc(ebpf_ffi::kLogBuffSize);
  memset(log_buf, 0, ebpf_ffi::kLogBuffSize);

  insn = (struct bpf_insn *)prog_buff;
  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.insns = (uint64_t)insn;
  attr.insn_cnt = (prog_size * sizeof(uint64_t)) / (sizeof(struct bpf_insn));
  attr.license = (uint64_t) "GPL";
  attr.log_size = ebpf_ffi::kLogBuffSize;
  attr.log_buf = (uint64_t)log_buf;
  attr.log_level = 3;

  int program_fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  if (program_fd < 0) {
    *error = strerror(errno);
  }

  *verifier_log =
      std::string((const char *)log_buf, strlen((const char *)log_buf));

  free(log_buf);
  return program_fd;
}

// Retrieves all the elements in a bpf map, returns a serialized MapElements
// proto message.
struct bpf_result ffi_get_map_elements(int map_fd, uint64_t map_size) {
  MapElements res;
  std::vector<uint64_t> elements;
  std::string error_message;
  if (!get_map_elements(map_fd, map_size, &elements, &error_message)) {
    res.set_error_message(error_message);
    return serialize_proto(res);
  }
  auto proto_elements = res.mutable_elements();
  proto_elements->Add(elements.begin(), elements.end());
  return serialize_proto(res);
}

bool get_map_elements(int map_fd, size_t map_size, std::vector<uint64_t> *res,
                      std::string *error) {
  for (uint64_t key = 0; key < map_size; key++) {
    uint64_t element = 0;
    union bpf_attr lookup_map = {.map_fd = static_cast<uint32_t>(map_fd),
                                 .key = reinterpret_cast<uint64_t>(&key),
                                 .value = reinterpret_cast<uint64_t>(&element)};
    int err =
        syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map));
    if (err < 0) {
      *error = strerror(errno);
      return false;
    }
    res->push_back(element);
  }
  return true;
}

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
                   unsigned int value_size, unsigned int max_entries) {
  union bpf_attr attr = {.map_type = map_type,
                         .key_size = key_size,
                         .value_size = value_size,
                         .max_entries = max_entries};

  return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int ffi_create_bpf_map(size_t size) {
  return bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t),
                        size);
}

bool execute_error(std::string *error_message, const char *strerr,
                   int *sockets) {
  if (sockets != nullptr) {
    close(sockets[0]);
    close(sockets[1]);
  }
  *error_message = strerr;
  return false;
}

struct bpf_result return_error(std::string error_message,
                               ExecutionResult *result) {
  result->set_did_succeed(false);
  result->set_error_message(error_message);
  return serialize_proto(*result);
}

struct bpf_result ffi_execute_bpf_program(void *serialized_proto,
                                          size_t length) {
  ExecutionResult execution_result;

  std::string serialized_proto_string(
      reinterpret_cast<const char *>(serialized_proto), length);
  ExecutionRequest execution_request;
  if (!execution_request.ParseFromString(serialized_proto_string)) {
    return return_error("Could not parse ExecutionRequest proto",
                        &execution_result);
  }

  int prog_fd = execution_request.prog_fd();
  uint8_t *data;
  uint8_t backup_data[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  data = backup_data;
  int data_size = 4;
  if (execution_request.input_data().length() != 0) {
    data = (uint8_t *)(execution_request.input_data().c_str());
    data_size = execution_request.input_data().length();
  }

  std::string error_message;
  if (!execute_bpf_program(prog_fd, data, data_size, &error_message)) {
    return return_error(error_message, &execution_result);
  }

  execution_result.set_did_succeed(true);
  return serialize_proto(execution_result);
}

bool execute_bpf_program(int prog_fd, uint8_t *input, int input_length,
                         std::string *error_message) {
  int socks[2] = {};
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0) {
    return execute_error(error_message, strerror(errno), NULL);
  }

  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
                 sizeof(prog_fd)) != 0) {
    return execute_error(error_message, strerror(errno), socks);
  }

  if (write(socks[1], input, input_length) != input_length) {
    return execute_error(error_message, "Could not write all data to socket",
                         socks);
  }

  close(socks[0]);
  close(socks[1]);
  return true;
}

void ffi_close_fd(int prog_fd) { close(prog_fd); }

int ffi_update_map_element(int map_fd, int key, uint64_t value) {
  union bpf_attr attr = {
      .map_fd = (unsigned int)map_fd,
      .key = (unsigned long)&key,
      .value = (unsigned long)&value,
      .flags = 0,  // No flags needed for a simple update
  };
  return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
