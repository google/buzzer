package main

import (
	"buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/units/units"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	"flag"
	"fmt"
	jsonpb "github.com/golang/protobuf/jsonpb"
	"os"
	"strings"
)

var (
	samplePath = flag.String("sample", "", "JSON sample of the ebpf program to minimize")
)

func main() {
	flag.Parse()
	fmt.Println("hello world!")

	ffi := &units.FFI{
		MetricsUnit: nil,
	}

	encodedProto, err := os.ReadFile(*samplePath)

	if err != nil {
		fmt.Printf("error reading file: %v\n")
		return
	}

	program := &epb.Program{}
	err = jsonpb.UnmarshalString(string(encodedProto), program)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ebpf.GeneratePoc(program, func(prog *epb.Program) bool {
		encodedProg, encodedFuncInfo, err := ebpf.EncodeInstructions(prog)

		if err != nil {
			fmt.Printf("Encoding error: %v\n", err)
			return false
		}

		encodedProgram := &fpb.EncodedProgram{
			Program:  encodedProg,
			Btf:      prog.Btf,
			Function: encodedFuncInfo,
			Maps:     prog.Maps,
		}
		validationResult, err := ffi.ValidateEbpfProgram(encodedProgram)
		defer func() {
			ffi.CleanFdArray(validationResult.FdArrayAddr, len(prog.Maps))
		}()
		ebpf.LatestLogMinimizer = validationResult.VerifierLog

		if !validationResult.IsValid {
			return false
		}

		defer func() {
			ffi.CloseFD(int(validationResult.ProgramFd))
		}()

		return strings.Contains(validationResult.VerifierLog, "verifier bug")

	})
	if err != nil {
		fmt.Printf("%v", err)
	}
}
