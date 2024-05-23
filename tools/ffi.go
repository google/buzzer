package main

import (
	"buzzer/pkg/ebpf/ebpf"
	"fmt"
	"unsafe"

	epb "buzzer/proto/ebpf_go_proto"
	jsonpb "github.com/golang/protobuf/jsonpb"
)

//#include <stdlib.h>
//#include <string.h>
import "C"

//export EncodeEBPF
func EncodeEBPF(serializedProgram unsafe.Pointer, serializedProgramSize C.int, encodingResult, encodingResultSize unsafe.Pointer) {

	// First reconstruct the proto.
	encodedPb := C.GoBytes(serializedProgram, serializedProgramSize)
	program := &epb.Program{}
	err := jsonpb.UnmarshalString(string(encodedPb), program)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Serialize it.
	encodedProg, err := ebpf.EncodeInstructions(program)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Then do magic to return it to C++
	// The 8 here is because every bpf instruction is an 8 byte number.
	cLength := C.ulong(len(encodedProg) * 8)

	// C++ will free the memory.
	resBuffer := C.malloc(cLength)
	C.memcpy(resBuffer, unsafe.Pointer(&encodedProg[0]), cLength)

	resultPtr := (**uint64)(encodingResult)
	*resultPtr = (*uint64)(resBuffer)

	resultSizePtr := (*uint64)(encodingResultSize)
	*resultSizePtr = uint64(len(encodedProg))
}

func main() {}
