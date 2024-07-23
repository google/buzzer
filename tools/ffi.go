package main

import (
	"buzzer/pkg/ebpf/ebpf"
	epb "buzzer/proto/ebpf_go_proto"
	"fmt"
	jsonpb "github.com/golang/protobuf/jsonpb"
	"unsafe"
)

//#include <stdlib.h>
//#include <string.h>
import "C"

//export EncodeEBPF
func EncodeEBPF(serializedProgram unsafe.Pointer, serializedProgramSize C.int,
	encodingResult unsafe.Pointer, encodingResultSize unsafe.Pointer,
	encodingBtf unsafe.Pointer, encodingBtfSize unsafe.Pointer,
	encodingfunc unsafe.Pointer, encodingfuncSize unsafe.Pointer) {

	// First reconstruct the proto.
	encodedPb := C.GoBytes(serializedProgram, serializedProgramSize)
	program := &epb.Program{}
	err := jsonpb.UnmarshalString(string(encodedPb), program)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Serialize it.
	encodedProg, encodedfunc, err := ebpf.EncodeInstructions(program)
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

	// Func
	funcLength := C.ulong(len(encodedfunc) * 8)

	// C++ will free the memory.
	funcBuffer := C.malloc(funcLength)
	C.memcpy(funcBuffer, unsafe.Pointer(&encodedfunc[0]), funcLength)

	funcPtr := (**uint64)(encodingfunc)
	*funcPtr = (*uint64)(funcBuffer)

	funcSizePtr := (*uint64)(encodingfuncSize)
	*funcSizePtr = uint64(len(encodedfunc))

	// BTF
	encodedBtf, err := ebpf.GetBtf()
	if err != nil {
		fmt.Println(err)
		return
	}
	btfLength := C.ulong(len(encodedBtf) * 8)

	// C++ will free the memory.
	btfBuffer := C.malloc(btfLength)
	C.memcpy(btfBuffer, unsafe.Pointer(&encodedBtf[0]), btfLength)

	btfPtr := (**uint64)(encodingBtf)
	*btfPtr = (*uint64)(btfBuffer)

	btfSizePtr := (*uint64)(encodingBtfSize)
	*btfSizePtr = uint64(len(encodedBtf))

}

func main() {}
