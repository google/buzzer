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

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
    default_visibility = [
        "//visibility:public",
    ],
)

go_library(
    name = "ebpf",
    srcs = [
        "alu_operations.go",
        "base_structures.go",
        "constants.go",
        "encoding_functions.go",
        "generation_utils.go",
        "jmp_operations.go",
        "poc_generator.go",
        "program.go",
        "st_ld_operations.go",
    ],
    cdeps = [
        "//ebpf_ffi",
    ],
    cgo = 1,
    importpath = "buzzer/pkg/ebpf/ebpf",
    deps = [
        "//pkg/rand",
    ],
)

go_test(
    name = "ebpf_test",
    srcs = [
        "alu_operations_test.go",
        "instruction_helpers_test.go",
        "jmp_operations_test.go",
        "program_test.go",
        "st_ld_operations_test.go",
    ],
    embed = [":ebpf"],
    importpath = "buzzer/pkg/ebpf",
)
