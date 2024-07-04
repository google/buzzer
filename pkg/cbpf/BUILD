# Copyright 2024 Google LLC
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

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

go_library(
    name = "cbpf",
    srcs = [
        "alu_instructions.go",
        "constants.go",
        "jmp_instructions.go",
        "st_ld_instructions.go",
    ],
    cgo = 1,
    importpath = "buzzer/pkg/cbpf/cbpf",
    deps = [
        "//proto:cbpf_go_proto",
        "@com_github_golang_protobuf//jsonpb",
    ],
)

go_test(
    name = "cbpf_test",
    srcs = [
        "alu_instructions_test.go",
        "jmp_instructions_test.go",
        "st_ld_instructions_test.go",
    ],
    embed = [":cbpf"],
    importpath = "buzzer/pkg/cbpf",
    deps = [
        "//proto:cbpf_go_proto",
        "@com_github_golang_protobuf//proto",
    ],
)
