// Copyright 2023 Google LLC
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

package ebpf

import (
	pb "buzzer/proto/ebpf_go_proto"
)

func newJmpInstruction[T Src](oc pb.JmpOperationCode, insclass pb.InsClass, dst pb.Reg, src T, offset int16) *pb.Instruction {
	var srcType pb.SrcOperand
	var srcReg pb.Reg
	var imm int32
	switch any(src).(type) {
	case pb.Reg:
		srcType = pb.SrcOperand_RegSrc
		srcReg = any(src).(pb.Reg)
		imm = 0
	case int:
		srcType = pb.SrcOperand_Immediate
		srcReg = pb.Reg_R0
		intImm := any(src).(int)
		imm = int32(intImm)
	default:
		srcType = pb.SrcOperand_Immediate
		srcReg = pb.Reg_R0
		imm = any(src).(int32)
	}

	return &pb.Instruction{
		Opcode: &pb.Instruction_JmpOpcode{
			JmpOpcode: &pb.JmpOpcode{
				OperationCode:    oc,
				Source:           srcType,
				InstructionClass: insclass,
			},
		},
		DstReg: dst,
		SrcReg: srcReg,
		// Oh protobuf why don't you have int16 support?, need to cast
		// this to int32 to make golang happy.
		Offset:    int32(offset),
		Immediate: imm,
		PseudoInstruction: &pb.Instruction_Empty{
			Empty: &pb.Empty{},
		},
	}
}

// Jmp represents an inconditional jump of `offset` instructions.
func Jmp(offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJA, pb.InsClass_InsClassJmp, pb.Reg_R0, int32(UnusedField), offset)
}

func JmpEQ[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJEQ, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpEQ32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJEQ, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpGT[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGT, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpGT32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGT, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpGE[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGE, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpGE32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGE, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpSET[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSET, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpSET32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSET, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpNE[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJNE, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpNE32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJNE, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpSGT[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSGT, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpSGT32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSGT, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpSGE[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSGE, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpSGE32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSGE, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func Call(functionValue int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpCALL, pb.InsClass_InsClassJmp, pb.Reg_R0, functionValue, int16(UnusedField))
}

func LdFunctionPtr(Imm int32) *pb.Instruction {
	return &pb.Instruction{
		Opcode: &pb.Instruction_MemOpcode{
			MemOpcode: &pb.MemOpcode{
				Mode:             pb.StLdMode_StLdModeIMM,
				Size:             pb.StLdSize_StLdSizeDW,
				InstructionClass: pb.InsClass_InsClassLd,
			},
		},
		DstReg:    R2,
		SrcReg:    pb.Reg_R4,
		Offset:    0,
		Immediate: Imm,
		PseudoInstruction: &pb.Instruction_PseudoValue{
			PseudoValue: &pb.Instruction{
				Opcode: &pb.Instruction_MemOpcode{
					MemOpcode: &pb.MemOpcode{
						Mode:             0,
						Size:             0,
						InstructionClass: 0,
					},
				},
				DstReg:    0,
				SrcReg:    0,
				Offset:    0,
				Immediate: 0,
				PseudoInstruction: &pb.Instruction_Empty{
					Empty: &pb.Empty{},
				},
			},
		},
	}

}

// LdMapElement loads a map element ptr to R0.
// It does the following operations:
// - Set R1 to the pointer of the target map.
// - Stores `element` at keyPtr + offset: *(u32 *)(keyPtr + offset) = element
// - Sets R2 to hold (keyPtr + offset)
// - Calls map_lookup_element
func LdMapElement(mapPtr pb.Reg, element int32, keyPtr pb.Reg, offset int16) ([]*pb.Instruction, error) {
	return InstructionSequence(
		Mov64(pb.Reg_R1, mapPtr),
		StW(keyPtr, element, offset),
		Mov64(pb.Reg_R2, keyPtr),
		Add64(pb.Reg_R2, int32(offset)),
		Call(MapLookup),
	)
}

// CallSkbLoadBytesRelative sets up the state of the registers to invoke the
// skb_load_bytes_relative helper function.
//
// The invocation of this function would look more or less like this:
// skb_load_bytes_relative(skb, skb_offset, dstAddress + dstAddressOffset, length, start_header).
func CallSkbLoadBytesRelative[T Src](skb pb.Reg, skb_offset T, dstAddress pb.Reg, dstAddressOffset T, length T, start_header T) ([]*pb.Instruction, error) {
	return InstructionSequence(
		Mov64(pb.Reg_R1, skb),
		Mov64(pb.Reg_R2, skb_offset),
		Mov64(pb.Reg_R3, dstAddress),
		Add64(pb.Reg_R3, dstAddressOffset),
		Mov64(pb.Reg_R4, length),
		Mov64(pb.Reg_R5, start_header),
		Call(SkbLoadBytesRelative),
	)
}

func Exit() *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpExit, pb.InsClass_InsClassJmp, pb.Reg_R0, int32(UnusedField), int16(UnusedField))
}

func JmpLT[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJLT, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpLT32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJLT, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpLE[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJLE, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpLE32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJLE, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpSLT[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSLT, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpSLT32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSLT, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}

func JmpSLE[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSLE, pb.InsClass_InsClassJmp, dstReg, src, offset)
}

func JmpSLE32[T Src](dstReg pb.Reg, src T, offset int16) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSLE, pb.InsClass_InsClassJmp32, dstReg, src, offset)
}
