package main

import (
	"buzzer/pkg/ebpf/ebpf"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	"fmt"
	jsonpb "github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"unsafe"
)

//#include <stdlib.h>
//#include <string.h>
import "C"

//export EncodeEBPF
func EncodeEBPF(serializedProgram unsafe.Pointer, serializedProgramSize C.int,
	serialized_proto unsafe.Pointer, size unsafe.Pointer,map_fd int32) {

	// First reconstruct the proto.
	encodedPb := C.GoBytes(serializedProgram, serializedProgramSize)
	program := &epb.Program{}
	err := jsonpb.UnmarshalString(string(encodedPb), program)
	if err != nil {
		fmt.Println(err)
		return
	}
	//fix mapFd 
	functions := program.Functions[0]
	ins := functions.Instructions
	insCount := len(ins)
	ins[insCount-20].Immediate = map_fd
	// Serialize it.
	encodedProg, encodedfunc, err := ebpf.EncodeInstructions(program)
	if err != nil {
		fmt.Println(err)
		return
	}

	result := &fpb.EncodedProgram{
		Program:  encodedProg,
		Function: encodedfunc,
		Btf:      program.Btf,
	}
	// Then do magic to return it to C++
	serializedProto, err := proto.Marshal(result)
	serializedSize := C.ulong(len(serializedProto))

	serializedBuffer := C.malloc(serializedSize)
	C.memcpy(serializedBuffer, unsafe.Pointer(&serializedProto[0]), serializedSize)

	serializedPtr := (**uint64)(serialized_proto)
	*serializedPtr = (*uint64)(serializedBuffer)

	sizePtr := (*uint64)(size)
	*sizePtr = uint64(len(serializedProto))
}

func main() {}
