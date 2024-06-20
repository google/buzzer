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

package cbpf

import (
	pb "buzzer/proto/cbpf_go_proto"
)

func newJmpInstruction(oc pb.JmpOperationCode, insClass pb.InsClass, jmpTrue int32,
	jmpFalse int32, fieldK int32) *pb.Instruction {

	opcode := int32(0)

	// The 3 least significant bits are the instruction class.
	opcode |= (int32(insClass) & 0x07)

	// The fourth bit is the source operand.
	opcode |= (int32(pb.SrcOperand_Immediate) & 0x08)

	// Finally the 4 MSB are the operation code.
	opcode |= (int32(oc) & 0xF0)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     jmpTrue,
		Jf:     jmpFalse,
		K:      fieldK,
	}
}

func JmpJA(jmpTrue int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJA, pb.InsClass_InsClassJmp, jmpTrue, int32(UnusedField), int32(UnusedField))
}

func JmpEQ(jmpTrue int32, jmpFalse int32, k int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJEQ, pb.InsClass_InsClassJmp, jmpTrue, jmpFalse, k)
}

func JmpGT(jmpTrue int32, jmpFalse int32, k int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGT, pb.InsClass_InsClassJmp, jmpTrue, jmpFalse, k)
}

func JmpGE(jmpTrue int32, jmpFalse int32, k int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJGE, pb.InsClass_InsClassJmp, jmpTrue, jmpFalse, k)
}

func JmpSET(jmpTrue int32, jmpFalse int32, k int32) *pb.Instruction {
	return newJmpInstruction(pb.JmpOperationCode_JmpJSET, pb.InsClass_InsClassJmp, jmpTrue, jmpFalse, k)
}
