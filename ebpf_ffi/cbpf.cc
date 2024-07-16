// Copyright 2024 Google LLC
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

#include "ebpf_ffi/cbpf.h"

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <netpacket/packet.h>

namespace cbpf_ffi {

// This constant was determined arbitrarily, the number of 0's has incremented
// when the size was no longer enough for the verifier logs.
constexpr size_t kLogBuffSize = 100000000;
}  // namespace cbpf_ffi

void load_cbpf_program(void *prog_buff, std::string *error, int *socks) {
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0) {
    *error = strerror(errno);
  }

  // cBPF programs have two relevant structures: sock_filter, and sock_fprog
  // https://www.kernel.org/doc/html/latest/networking/filter.html#structure
  struct sock_filter *insn = (struct sock_filter *)prog_buff;
  struct sock_fprog program;
  int size = sizeof(insn);
  program.len = size / sizeof(insn[0]);
  program.filter = insn;

  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_FILTER, &program,
                 sizeof(program)) < 0) {
    *error = strerror(errno);
  }
}

struct bpf_result ffi_load_cbpf_program(void *prog_buff, int coverage_enabled,
                                        uint64_t coverage_size) {
  std::string error_message;

  struct coverage_data cover;
  memset(&cover, 0, sizeof(struct coverage_data));
  cover.fd = -1;
  cover.coverage_size = coverage_size;
  if (coverage_enabled) enable_coverage(&cover);

  int socks[2] = {};
  load_cbpf_program(prog_buff, &error_message, socks);

  ValidationResult vres;
  if (coverage_enabled) get_coverage_and_free_resources(&cover, &vres);

  // Start building the validation result proto.
  vres.set_socket_parent(socks[0]);
  vres.set_socket_child(socks[1]);
  if (cover.fd != -1) {
    vres.set_did_collect_coverage(true);
    vres.set_coverage_size(cover.coverage_size);
    vres.set_coverage_buffer(reinterpret_cast<uint64_t>(cover.coverage_buffer));
  } else {
    vres.set_did_collect_coverage(false);
  }

  if (socks[0] < 0) {
    // Return why we failed to load the program.
    vres.set_bpf_error(error_message);
    vres.set_is_valid(false);
  } else {
    vres.set_is_valid(true);
  }

  return serialize_proto(vres);
}

bool execute_cbpf_program(int socket_parent, int socket_child, uint8_t *input,
                          int input_length, std::string *error_message) {
  if (write(socket_child, input, input_length) != input_length) {
    *error_message = "Could not write all data to socket";
    return false;
  }

  close(socket_parent);
  close(socket_child);

  return true;
}

struct bpf_result ffi_execute_cbpf_program(void *serialized_proto,
                                           size_t length) {
  ExecutionResult execution_result;

  std::string serialized_proto_string(
      reinterpret_cast<const char *>(serialized_proto), length);
  CbpfExecutionRequest execution_request;
  if (!execution_request.ParseFromString(serialized_proto_string)) {
    return return_error("Could not parse ExecutionRequest proto",
                        &execution_result);
  }

  int socket_parent = execution_request.socket_parent();
  int socket_child = execution_request.socket_child();

  uint8_t *data;
  uint8_t backup_data[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  data = backup_data;
  int data_size = 4;
  if (execution_request.input_data().length() != 0) {
    data = (uint8_t *)(execution_request.input_data().c_str());
    data_size = execution_request.input_data().length();
  }

  std::string error_message;
  if (!execute_cbpf_program(socket_parent, socket_child, data, data_size,
                            &error_message)) {
    return return_error(error_message, &execution_result);
  }

  execution_result.set_did_succeed(true);
  return serialize_proto(execution_result);
}
