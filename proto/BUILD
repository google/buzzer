# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

proto_library(
    name = "ebpf_fuzzer_proto",
    srcs = ["ebpf_fuzzer.proto"],
    deps = [],
)

go_proto_library(
    name = "ebpf_fuzzer_go_proto",
    importpath = "buzzer/proto/ebpf_fuzzer_go_proto",
    protos = [":ebpf_fuzzer_proto"],
    deps = []
)

cc_proto_library(
    name = "ebpf_fuzzer_cc_proto",
    deps = [":ebpf_fuzzer_proto"],
)
