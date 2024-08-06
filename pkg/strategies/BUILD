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
    name = "strategies",
    srcs = [
        "base.go",
        "cbpf_playground.go",
        "cbpf_random_instruction.go",
        "coverage_based.go",
        "heap.go",
        "loop_pointer_arithmetic.go",
        "playground.go",
        "pointer_arithmetic.go",
    ],
    importpath = "buzzer/pkg/strategies/strategies",
    deps = [
        "//pkg/cbpf",
        "//pkg/ebpf",
        "//pkg/rand",
        "//pkg/units",
        "//proto:btf_go_proto",
        "//proto:cbpf_go_proto",
        "//proto:ebpf_go_proto",
        "//proto:ffi_go_proto",
        "//proto:program_go_proto",
        "@com_github_golang_protobuf//proto",
    ],
)

go_test(
    name = "strategies_test",
    srcs = [
        "heap_test.go",
    ],
    embed = [":strategies"],
    importpath = "buzzer/pkg/strategies/strategies/strategies",
    deps = [],
)
