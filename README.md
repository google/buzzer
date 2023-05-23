# Buzzer - An eBPF Fuzzer toolchain

![ci_status](https://github.com/google/buzzer/actions/workflows/ci.yml/badge.svg)


Buzzer is a fuzzer toolchain that allows to write eBPF _fuzzing strategies_.

A Fuzzing strategy is a way to generate random eBPF Programs and then validate
that they don't have unexpected behaviour.

To run the fuzzer follow the next steps

1. Install [bazel](https://bazel.build/).
1. Install [clang](https://clang.llvm.org/)
1. Setup the correct CC and CXX env variables
   ```
   export CC=clang
   export CXX=clang++
   ```
1. Run 
    ```
    bazel build :buzzer
    ```
1. Run buzzer either as root:
    ```
    sudo ./bazel-bin/buzzer_/buzzer
    ```
   
   OR with CAP_BPF:

    ```
    sudo setcap CAP_BPF=eip bazel-bin/buzzer_/buzzer
    ./bazel-bin/buzzer_/buzzer
    ```
## Documents:

* [Overall Architecture of Buzzer](docs/architecture/architecture.md)
* [How to run buzzer with coverage](docs/guides/running_with_coverage.md)

## Trophies
Did you find a cool bug using _Buzzer_? Let us know via a pull request! 
We'd like to collect all issues discovered with this framework under this
section.

* [CVE-2023-2163](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=71b547f561247897a0a14f3082730156c0533fed):
  An error in the branch pruning logic of the eBPF verifier can cause unsafe
  paths to not be explored. The unsafe pruned paths are the actual paths taken
  at runtime which causes a mismatch in what the verifier thinks the values of 
  certain registers are versus what they actually are. This mismatch can be
  abused to read/write arbitrary memory in the kernel by using the confused
  registers as base registers for memory operations.
