# Buzzer - An eBPF Fuzzer toolchain

Buzzer is a fuzzer toolchain that allows to write eBPF _fuzzing strategies_.

A Fuzzing strategy is a way to generate random eBPF Programs and then validate
that they don't have unexpected behaviour.

To run the fuzzer follow the next steps

1. Install [bazel](https://bazel.build/).
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

## Trophies
Did you find a cool bug using _Buzzer_? Let us know via a pull request! 
We'd like to collect all issues discovered with this framework under this
section.

* [CVE-2023-2163](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=71b547f561247897a0a14f3082730156c0533fed):
  An error in the branch prunning logic of the eBPF Verifier can lead into unsafe
  paths not being explored and, this can lead to arbitrary kernel memory R/W.
