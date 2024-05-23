#include <google/protobuf/util/json_util.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>

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

  uint64_t *ebpf_instructions = NULL;
  uint64_t array_length = 0;
  EncodeEBPF(content.data(), content.length(), &ebpf_instructions,
             &array_length);

  if (!ebpf_instructions) {
    std::cerr << "failed to decode ebpf program" << std::endl;
    return -1;
  }

  for (size_t i = 0; i < array_length; i++) {
    printf("[%lu]: %02lx\n", i, ebpf_instructions[i]);
  }

  free(ebpf_instructions);
  return 0;
}
