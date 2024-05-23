#include <google/protobuf/util/json_util.h>

#include <fstream>
#include <iostream>
#include <string>

#include "proto/ebpf.pb.h"

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " path_to_ebpf.json" << std::endl;
    return -1;
  }
  // Read the serialized data from the file (replace with your transfer logic)
  std::fstream input(argv[1], std::ios::in | std::ios::binary);
  std::string content((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());

  // Create a Person message and parse the content
  ebpf::Program program;
  google::protobuf::util::JsonParseOptions options;
  // Adjust options if needed (e.g., ignore unknown fields)

  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(content, &program, options);

  if (!status.ok()) {
    std::cerr << "Failed to parse JSON: " << status.ToString() << std::endl;
    return -1;
  }

  // TODO: Implement loading the ebpf program.
  std::cout << "Deserialized Program:" << program.DebugString() << std::endl;

  return 0;
}
