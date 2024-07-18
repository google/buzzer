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
	pb "buzzer/proto/cbpf_go_proto"
)

func newJmpInstruction[T Src](oc pb.JmpOperationCode, jmpTrue, jmpFalse int32, src T) *pb.Instruction {
	var srcType pb.SrcOperand
	var k int32
	switch any(src).(type) {
	case pb.Reg:
		srcType = pb.SrcOperand_RegSrc
		k = int32(pb.Reg_X)
	case int32:
		srcType = pb.SrcOperand_Immediate
		k = int32(src)
	case int:
		srcType = pb.SrcOperand_Immediate
		k = int32(src)
	default:
		return nil
	}
	// The opcode field is divided into three parts, for more information go to:
	// https://www.infradead.org/~mchehab/kernel_docs/networking/filter.html#ebpf-opcode-encoding
	opcode := int32(0)

	// The 3 least significant bits are the instruction class.
	opcode |= (int32(pb.InsClass_InsClassJmp) & 0x07)

	// The fourth bit is the source operand.
	opcode |= (int32(srcType) & 0x08)

	// Finally the 4 MSB are the operation code.
	opcode |= (int32(oc) & 0xF0)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     jmpTrue,
		Jf:     jmpFalse,
		K:      k,
	}
}

func JmpJA(jmpTrue int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJA, jmpTrue, int32(UnusedField), int32(UnusedField))
}

func JmpEQ[T Src](jmpTrue, jmpFalse int32, k T) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJEQ, jmpTrue, jmpFalse, k)
}

func JmpGT[T Src](jmpTrue, jmpFalse int32, k T) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGT, jmpTrue, jmpFalse, k)
}

func JmpGE[T Src](jmpTrue, jmpFalse int32, k T) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGE, jmpTrue, jmpFalse, k)
}

func JmpSET[T Src](jmpTrue, jmpFalse int32, k T) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSET, jmpTrue, jmpFalse, k)
}
