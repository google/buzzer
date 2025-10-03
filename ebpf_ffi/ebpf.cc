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

#include "ebpf_ffi/ebpf.h"

#include <vector>

namespace ebpf_ffi {

// This constant was determined arbitrarily, the number of 0's has incremented
// when the size was no longer enough for the verifier logs.
constexpr size_t kLogBuffSize = 100000000;
// This constnat was determined arbitrarily for the btf logs
constexpr size_t btfKLogBuffSize = 1024;
}  // namespace ebpf_ffi

// btf_buff: Pointer to a buffer where the BTF data is stored
// btf_size: Size of the BTF data in bytes
int btf_load(void *btf_buff, size_t btf_size, std::string &error) {
  union bpf_attr btf_attr;
  memset(&btf_attr, 0, sizeof(btf_attr));
  btf_attr.btf = (uint64_t)btf_buff;
  btf_attr.btf_size = btf_size;

  char *btf_log_buf = (char *)malloc(ebpf_ffi::btfKLogBuffSize);
  memset(btf_log_buf, 0, ebpf_ffi::btfKLogBuffSize);
  btf_attr.btf_log_buf = (uint64_t)btf_log_buf;
  btf_attr.btf_log_size = ebpf_ffi::btfKLogBuffSize;
  btf_attr.btf_log_level = 2;

  int btf_fd = syscall(SYS_bpf, BPF_BTF_LOAD, &btf_attr, sizeof(btf_attr));
  if (btf_fd < 0) {
    error = strerror(errno);
  }
  return btf_fd;
}

uint64_t setup_bpf_maps(std::vector<ebpf::EbpfMap> maps) {
  size_t fd_array_size = sizeof(int) * maps.size();
  int *fd_array = (int *)malloc(fd_array_size);
  if (!fd_array) return 0;
  int i = 0;
  for (ebpf::EbpfMap map : maps) {
    int map_fd =
        bpf_create_map(static_cast<bpf_map_type>(map.type()), map.key_size(),
                       map.value_size(), map.max_entries());
    if (map_fd > 0) {
      int j = 0;
      for (uint64_t element : map.values()) {
        ffi_update_map_element(map_fd, j++, element);
      }
    }
    fd_array[i++] = map_fd;
  }
  return reinterpret_cast<uint64_t>(fd_array);
}

ValidationResult load_ebpf_program(EncodedProgram program, std::string &error) {
  struct bpf_insn *insn;
  ValidationResult res;
  union bpf_attr attr = {};

  // For the verifier log.
  unsigned char *log_buf = (unsigned char *)malloc(ebpf_ffi::kLogBuffSize);
  memset(log_buf, 0, ebpf_ffi::kLogBuffSize);

  int btf_fd = btf_load(((uint8_t *)(program.btf().c_str())),
                        (program.btf().length()), error);
  if (!(btf_fd < 0)) {
    struct bpf_func_info *func =
        (struct bpf_func_info *)((uint8_t *)(program.function().c_str()));
    attr.prog_btf_fd = btf_fd;
    attr.func_info_rec_size = sizeof(struct bpf_func_info);
    attr.func_info = (uint64_t)(func);
    attr.func_info_cnt =
        ((program.function().length()) / sizeof(struct bpf_func_info));
  }
  insn = (struct bpf_insn *)((uint8_t *)(program.program().c_str()));
  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.insns = (uint64_t)insn;
  attr.insn_cnt = ((program.program().length()) / (sizeof(struct bpf_insn)));
  attr.license = (uint64_t)"GPL";
  attr.log_size = ebpf_ffi::kLogBuffSize;
  attr.log_buf = (uint64_t)log_buf;
  attr.log_level = 2;

  if (program.maps().size() > 0) {
    uint64_t fd_array = setup_bpf_maps(std::vector<ebpf::EbpfMap>(
        program.maps().begin(), program.maps().end()));
    attr.fd_array = fd_array;
    res.set_fd_array_addr(fd_array);
  }

  int program_fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  if (program_fd < 0) {
    error = strerror(errno);
  }
  res.set_program_fd(program_fd);

  res.set_verifier_log(
      std::string((const char *)log_buf, strlen((const char *)log_buf)));

  free(log_buf);
  return res;
}

struct bpf_result ffi_load_ebpf_program(void *serialized_proto, size_t size,
                                        int coverage_enabled,
                                        uint64_t coverage_size) {
  std::string error_message;

  struct coverage_data cover;
  memset(&cover, 0, sizeof(struct coverage_data));
  cover.fd = -1;
  cover.coverage_size = coverage_size;
  if (coverage_enabled) enable_coverage(&cover);

  std::string serialized_proto_string(
      reinterpret_cast<const char *>(serialized_proto), size);
  EncodedProgram program;
  if (!program.ParseFromString(serialized_proto_string)) {
    error_message = "Could not parse EncodedProgram proto";
  }
  ValidationResult vres = load_ebpf_program(program, error_message);
  if (coverage_enabled) get_coverage_and_free_resources(&cover, &vres);

  if (cover.fd != -1) {
    vres.set_did_collect_coverage(true);
    vres.set_coverage_size(cover.coverage_size);
    vres.set_coverage_buffer(reinterpret_cast<uint64_t>(cover.coverage_buffer));
  } else {
    vres.set_did_collect_coverage(false);
  }

  if (vres.program_fd() < 0) {
    // Return why we failed to load the program.
    vres.set_bpf_error(error_message);
    vres.set_is_valid(false);
  } else {
    vres.set_is_valid(true);
  }

  return serialize_proto(vres);
}

bool get_map_elements(int map_fd, size_t map_size, std::vector<uint64_t> *res,
                      std::string &error) {
  for (uint64_t key = 0; key < map_size; key++) {
    uint64_t element = 0;
    union bpf_attr lookup_map = {.map_fd = static_cast<uint32_t>(map_fd),
                                 .key = reinterpret_cast<uint64_t>(&key),
                                 .value = reinterpret_cast<uint64_t>(&element)};
    int err =
        syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map));
    if (err < 0) {
      error = strerror(errno);
      return false;
    }
    res->push_back(element);
  }
  return true;
}

int ffi_update_map_element(int map_fd, int key, uint64_t value) {
  union bpf_attr attr = {
      .map_fd = (unsigned int)map_fd,
      .key = (unsigned long)&key,
      .value = (unsigned long)&value,
      .flags = 0,  // No flags needed for a simple update
  };
  return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
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

// Retrieves all the elements in a bpf map, returns a serialized MapElements
// proto message.
struct bpf_result ffi_get_map_elements(int map_fd, uint64_t map_size) {
  MapElements res;
  std::vector<uint64_t> elements;
  std::string error_message;
  if (!get_map_elements(map_fd, map_size, &elements, error_message)) {
    res.set_error_message(error_message);
    return serialize_proto(res);
  }
  auto proto_elements = res.mutable_elements();
  proto_elements->Add(elements.begin(), elements.end());
  return serialize_proto(res);
}

struct bpf_result ffi_get_map_elements_fd_array(uint64_t fd_array_addr,
                                                uint32_t idx,
                                                uint64_t map_size) {
  MapElements res;
  std::vector<uint64_t> elements;
  std::string error_message;

  int *fd_array = reinterpret_cast<int *>(fd_array_addr);
  int map_fd = fd_array[idx];

  return ffi_get_map_elements(map_fd, map_size);
}

bool execute_ebpf_program(int prog_fd, uint8_t *input, int input_length,
                          std::string &error_message) {
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

struct bpf_result ffi_execute_ebpf_program(void *serialized_proto,
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
  if (!execute_ebpf_program(prog_fd, data, data_size, error_message)) {
    return return_error(error_message, &execution_result);
  }

  execution_result.set_did_succeed(true);
  return serialize_proto(execution_result);
}

void ffi_clean_fd_array(unsigned long long int addr, int size) {
  int *fd_array = reinterpret_cast<int *>(addr);
  for (int i = 0; i < size; i++) {
    close(fd_array[size]);
  }
  free(fd_array);
}
