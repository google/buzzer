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
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/escaping.h"
#include "ffi.h"
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

struct coverage_data* kCoverageData = nullptr;

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

    void get_coverage(ValidationResult *vres) {
        if (kCoverageData == nullptr || kCoverageData->fd == -1) return;
        uint64_t trace_size = kCoverageData->coverage_buffer[0];

        auto *coverage_addresses = vres->mutable_coverage_address();
        absl::flat_hash_set<uint64_t> seen_address;
        for (uint64_t i = 0; i < trace_size; i++) {
            uint64_t addr = kCoverageData->coverage_buffer[i + 1];
            if (seen_address.find(addr) == seen_address.end()) {
                coverage_addresses->Add(addr);
                seen_address.insert(addr);
            }
        }
        vres->set_did_collect_coverage(true);
        vres->set_coverage_size(trace_size);
        return;
    }

    bool enable_coverage() {
        if (!kCoverageData || kCoverageData->fd == -1) return false;
        return ioctl(kCoverageData->fd, KCOV_ENABLE, KCOV_TRACE_PC) == 0;
    }

    void disable_coverage() {
        if (kCoverageData == nullptr || kCoverageData->fd == -1) return;
        (void)ioctl(kCoverageData->fd, KCOV_DISABLE, 0);
    }

    int ffi_setup_coverage() {
        if (!kCoverageData) {
            kCoverageData = (struct coverage_data*)malloc(sizeof(struct coverage_data));
            memset(kCoverageData, 0, sizeof(struct coverage_data));
        }

        int fd = open("/sys/kernel/debug/kcov", O_RDWR);
        kCoverageData->fd = fd;
        if (fd == -1) return -1;
        /* Setup trace mode and trace size. */
        if (ioctl(fd, KCOV_INIT_TRACE, KCOV_SIZE)) return -1;
        /* Mmap buffer shared between kernel- and user-space. */
        uint64_t *cover =
                (uint64_t *)mmap(nullptr, KCOV_SIZE * sizeof(uint64_t),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if ((void *)cover == MAP_FAILED) return -1;
        memset(cover, 0, KCOV_SIZE * sizeof(uint64_t));
        
        kCoverageData->fd = fd;
        kCoverageData->coverage_buffer = cover;
        return 0;
    }

    int ffi_cleanup_coverage() {
        if (!kCoverageData) return 0;

        close(kCoverageData->fd);
        munmap(kCoverageData->coverage_buffer, KCOV_SIZE * sizeof(uint64_t));
        free(kCoverageData);
        kCoverageData = nullptr;
        return 0;
    }

    bool execute_error(std::string &error_message, const char *strerr,
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
