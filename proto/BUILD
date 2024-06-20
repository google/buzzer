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

load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

proto_library(
    name = "ebpf_proto",
    srcs = ["ebpf.proto"],
    deps = [],
)

go_proto_library(
    name = "ebpf_go_proto",
    importpath = "buzzer/proto/ebpf_go_proto",
    protos = [":ebpf_proto"],
    deps = [],
)

cc_proto_library(
    name = "ebpf_cc_proto",
    deps = [":ebpf_proto"],
)

proto_library(
    name = "ffi_proto",
    srcs = ["ffi.proto"],
    deps = [],
)

go_proto_library(
    name = "ffi_go_proto",
    importpath = "buzzer/proto/ffi_go_proto",
    protos = [":ffi_proto"],
    deps = [],
)

cc_proto_library(
    name = "ffi_cc_proto",
    deps = [":ffi_proto"],
)

proto_library(
    name = "cbpf_proto",
    srcs = ["cbpf.proto"],
    deps = [],
)

go_proto_library(
    name = "cbpf_go_proto",
    importpath = "buzzer/proto/cbpf_go_proto",
    protos = [":cbpf_proto"],
    deps = [],
)

cc_proto_library(
    name = "cbpf_cc_proto",
    deps = [":cbpf_proto"],
)
