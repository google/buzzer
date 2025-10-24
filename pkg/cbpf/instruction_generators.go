// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cbpf

import (
	"buzzer/pkg/rand"
	pb "buzzer/proto/cbpf_go_proto"
)

func generateImmAluInstruction(op pb.AluOperationCode) *pb.Instruction {
	value := int32(rand.SharedRNG.RandRange(0, 0xFFFFFFFF))
	switch op {
	case pb.AluOperationCode_AluRsh, pb.AluOperationCode_AluLsh:
		value = value % 32
		if value < 0 {
			value *= -1
		}
	}
	return newAluInstruction(op, value)
}

func RandomAluInstruction() *pb.Instruction {
	op := pb.AluOperationCode(rand.SharedRNG.RandRange(0x00, 0x0a) << 4)
	var instr *pb.Instruction
	if rand.SharedRNG.RandRange(0, 1) == 0 {
		instr = generateImmAluInstruction(op)
	} else {
		instr = newAluInstruction(op, X)
	}

	return instr
}

func RandomJmpInstruction(maxOffset uint64) *pb.Instruction {
	var op pb.JmpOperationCode

	for {
		op = pb.JmpOperationCode(rand.SharedRNG.RandRange(0x00, 0x04) << 4)
		if op != pb.JmpOperationCode_JmpJA {
			break
		}
	}

	offset := int8(rand.SharedRNG.RandRange(1, maxOffset))
	if rand.SharedRNG.RandBool()  {
		src := int32(rand.SharedRNG.RandRange(0, 0xffffffff))
		return newJmpInstruction(op, 0, int32(offset), src)
	} else {
		src := X
		return newJmpInstruction(op, 0, int32(offset), src)
	}
}

// RandomSize is a helper function to be used in the RandomMemInstruction
// functions. The result of this function should be one of the recognized
// operation sizes of cbpf
func RandomSize() pb.StLdSize {
	size := rand.SharedRNG.RandInt() % 3
	// The possible size values of instructions are
	// W: 0x00
	// H: 0x08
	// B: 0x10
	// We can generate these values with a shift to the left of 3 bits.
	size = size << 3
	return pb.StLdSize(size)
}

func AlignmentForSize(s pb.StLdSize) int16 {
	switch s {
	case pb.StLdSize_StLdSizeB:
		return 1
	case pb.StLdSize_StLdSizeH:
		return 2
	case pb.StLdSize_StLdSizeW:
		return 4
	default:
		// We shouldn't reach this.
		return 0
	}
}

func RandomOffset(s pb.StLdSize) int16 {
	// Cap offsets to 512.
	maxOffset := int16(512)
	offset := int16(rand.SharedRNG.RandInt()) % maxOffset
	for offset == 0 {
		offset = int16(rand.SharedRNG.RandInt()) % maxOffset
	}

	if offset > 0 {
		// Mem offsets from the stack can only be negative.
		offset = offset * -1
	}

	// Align the offset according to the size.
	for offset%AlignmentForSize(s) != 0 {
		offset = offset - 1
	}

	return offset
}

func RandomMode() pb.StLdMode {
	return pb.StLdMode(rand.SharedRNG.RandRange(0x00, 0x08) << 4)
}

func RandomStoreInstruction() *pb.Instruction {
	mode := pb.StLdMode_StLdModeMEM
	size := RandomSize()
	imm := int32(rand.SharedRNG.RandRange(0, 512))

	t := rand.SharedRNG.RandInt() % 2
	switch t {
	case 0:
		return newStoreLoadOperation(mode, size, pb.InsClass_InsClassSt, imm)
	default:
		return newStoreLoadOperation(mode, size, pb.InsClass_InsClassStx, imm)
	}

}

func RandomLoadImm(mode pb.StLdMode) int32 {
	switch mode {
	case pb.StLdMode_StLdModeABS:
		return int32(ExtensionOffset + pb.Extensions(rand.SharedRNG.RandRange(0, 64)))
	default:
		return int32(rand.SharedRNG.RandRange(0, 512))
	}
}

func RandomLoadInstruction() *pb.Instruction {
	mode := RandomMode()
	size := RandomSize()
	imm := RandomLoadImm(mode)

	t := rand.SharedRNG.RandInt() % 2
	switch t {
	case 0:
		return newStoreLoadOperation(mode, size, pb.InsClass_InsClassLd, imm)
	default:
		return newStoreLoadOperation(mode, size, pb.InsClass_InsClassLdx, imm)
	}
}
