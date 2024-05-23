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

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

go_binary(
    name = "ffi",
    srcs = ["ffi.go"],
    out = "ffi.so",
    cgo = 1,
    importpath = "buzzer/tools/ffi",
    linkmode = "c-shared",
    deps = [
        "//pkg/ebpf",
        "//proto:ebpf_go_proto",
        "@com_github_golang_protobuf//jsonpb",
    ],
)

cc_binary(
    name = "loader",
    srcs = ["loader.cc"],
    deps = [
        ":ffi.cc",
        "//proto:ebpf_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)
