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
