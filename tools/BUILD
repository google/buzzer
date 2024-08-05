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
    out = "ffi.a",
    cgo = 1,
    gc_linkopts = [
        "-extldflags",
        "-static",
    ],
    importpath = "buzzer/tools/ffi",
    linkmode = "c-archive",
    deps = [
        "//pkg/ebpf",
        "//proto:ebpf_go_proto",
        "//proto:ffi_go_proto",
        "@com_github_golang_protobuf//jsonpb",
        "@com_github_golang_protobuf//proto",
    ],
)

cc_binary(
    name = "loader",
    srcs = ["loader.cc"],
    features = ["fully_static_link"],
    deps = [
        ":ffi.cc",
        "//ebpf_ffi",
        "//proto:ebpf_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)
