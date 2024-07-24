#include <google/protobuf/util/json_util.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>

#include "ebpf_ffi/ebpf.h"
#include "ffi.h"
#include "proto/ebpf.pb.h"

extern "C" {
void EncodeEBPF(void *, int, void *, void *);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " path_to_ebpf.json" << std::endl;
    return -1;
  }

  std::fstream input(argv[1], std::ios::in | std::ios::binary);
  std::string content((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());

  void *serialized_proto = NULL;
  size_t size = 0;
  EncodeEBPF(content.data(), content.length(), &serialized_proto, &size);

  if (!serialized_proto) {
    std::cerr << "failed to decode ebpf program" << std::endl;
    return -1;
  }

  const int map_size = 2;
  int map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t),
                              sizeof(uint64_t), map_size);
  std::string verifier_log, error_message;

  int prog_fd =
      load_ebpf_program(&serialized_proto, size, &verifier_log, error_message);
  std::cout << "Verifier log: " << std::endl << verifier_log;

  if (prog_fd < 0) {
    std::cerr << "could not load bpf program: " << error_message << std::endl;
    return -1;
  }

  uint8_t socket_input[2] = {0xAA, 0xAA};
  if (!execute_ebpf_program(prog_fd, socket_input, sizeof(socket_input),
                            error_message)) {
    std::cerr << "error executing program " << error_message << std::endl;
    return -1;
  }

  std::vector<uint64_t> map_elements;
  if (!get_map_elements(map_fd, map_size, &map_elements, error_message)) {
    std::cerr << "Could not get map elements: " << error_message << std::endl;
    return -1;
  }

  std::cout << "map elements: " << std::endl;
  for (auto element : map_elements) {
    std::cout << "element: " << element << std::endl;
  }

  free(serialized_proto);
  return 0;
}
