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

bool load_cbpf_program(void *prog_buff, size_t size, std::string &error,
                       int *socks) {
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0) {
    error = strerror(errno);
    return false;
  }
  // cBPF programs have two relevant structures: sock_filter, and sock_fprog
  // https://www.kernel.org/doc/html/latest/networking/filter.html#structure
  struct sock_filter *insn = (struct sock_filter *)prog_buff;
  struct sock_fprog program;
  program.len = size;
  program.filter = insn;

  // Timeout added in case the filter drops a packet
  struct timeval tv;
  tv.tv_sec = 0;
  // The amount of time for timeout was determined arbitrarly
  tv.tv_usec = 10000;
  if (setsockopt(socks[1], SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
                 sizeof tv) < 0) {
    error = strerror(errno);
    goto out_error;
  }
   if (setsockopt(socks[1], SOL_SOCKET, SO_ATTACH_FILTER, &program,
                 sizeof(program)) < 0) {
    error = strerror(errno);
    goto out_error;
  }
  return true;
out_error:
  close(socks[0]);
  close(socks[1]);
  return false;
}

struct bpf_result validation_error(std::string error_message,
                                   ValidationResult *vres) {
  vres->set_bpf_error(error_message);
  vres->set_is_valid(false);
  return serialize_proto(*vres);
}

struct bpf_result ffi_load_cbpf_program(void *prog_buff, size_t size,
                                        int coverage_enabled,
                                        uint64_t coverage_size) {
  std::string error_message;

  struct coverage_data cover;
  memset(&cover, 0, sizeof(struct coverage_data));
  cover.fd = -1;
  cover.coverage_size = coverage_size;
  if (coverage_enabled) enable_coverage(&cover);

  ValidationResult vres;

  int socks[2] = {-1, -1};
  if (!load_cbpf_program(prog_buff, size, error_message, socks)) {
    // Return why we failed to load the program.
    if (coverage_enabled) get_coverage_and_free_resources(&cover, &vres);
    return validation_error(error_message, &vres);
  }

  if (coverage_enabled) get_coverage_and_free_resources(&cover, &vres);

  // Start building the validation result proto.
  vres.set_socket_write(socks[0]);
  vres.set_socket_read(socks[1]);
  if (cover.fd != -1) {
    vres.set_did_collect_coverage(true);
    vres.set_coverage_size(cover.coverage_size);
    vres.set_coverage_buffer(reinterpret_cast<uint64_t>(cover.coverage_buffer));
  } else {
    vres.set_did_collect_coverage(false);
  }

  if (socks[0] < 0) {
    // Return why we failed to load the program.
    return validation_error(error_message, &vres);
  }
  vres.set_is_valid(true);

  return serialize_proto(vres);
}

bool execute_cbpf_program(int socket_write, int socket_read, uint8_t *input,
                          uint8_t *output, int input_length,
                          std::string &error_message) {
  if (write(socket_write, input, input_length) != input_length) {
    error_message = "Could not write all data to socket";
    goto out
  }

  close(socket_write);
  if (read(socket_read, output, input_length) != input_length) {
    error_message = "Could not read all data to socket";
    goto out
  }
  close(socket_read);

  return true;

out:
  close(socket_write);
  close(socket_read);
  return false;
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

  int socket_write = execution_request.socket_write();
  if (socket_write < 0) {
    return return_error("Invalid socket parent", &execution_result);
  }
  int socket_read = execution_request.socket_read();
  if (socket_read < 0) {
    return return_error("Invalid socket child", &execution_result);
  }

  uint8_t *data;
  uint8_t backup_data[4] = {0xAA, 0xAA, 0xAA, 0xAA};
  data = backup_data;
  int data_size = 4;
  if (execution_request.input_data().length() != 0) {
    data = (uint8_t *)(execution_request.input_data().c_str());
    data_size = execution_request.input_data().length();
  }

  uint8_t *read_data;
  uint8_t backup_read_data[data_size + 1];
  read_data = backup_read_data;

  memset(read_data, 0x00, data_size + 1);
  std::string error_message;
  if (!execute_cbpf_program(socket_write, socket_read, data, read_data,
                            data_size, error_message)) {
    return return_error(error_message, &execution_result);
  }

  std::string string_data = (const char *)read_data;
  execution_result.set_output_data(string_data);

  execution_result.set_did_succeed(true);
  return serialize_proto(execution_result);
}
