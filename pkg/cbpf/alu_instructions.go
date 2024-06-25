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

type Src interface {
	pb.Reg | int32
}

func newAluInstruction[T Src](oc pb.AluOperationCode, src T) *pb.Instruction {
	var srcType pb.SrcOperand
	var k int32
	switch any(src).(type) {
	case pb.Reg:
		srcType = pb.SrcOperand_RegSrc
		k = int32(pb.Reg_X)
	case int32:
		srcType = pb.SrcOperand_Immediate
		k = int32(src)
	}
	opcode := int32(0)

	// The 3 least significant bits are the instruction class.
	opcode |= int32(pb.InsClass_InsClassAlu & 0x07)

	// The fourth bit is the source operand.
	opcode |= int32(srcType & 0x08)

	// Finally the 4 MSB are the operation code.
	opcode |= int32(oc & 0xF0)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     0,
		Jf:     0,
		K:      k,
	}
}

func Ret[T Src](src T) *pb.Instruction {
	var srcType pb.SrcOperand
	var k int32
	switch any(src).(type) {
	case pb.Reg:
		srcType = pb.SrcOperand_RegSrc
		k = int32(pb.Reg_A)
	case int32:
		srcType = pb.SrcOperand_Immediate
		k = int32(src)
	}
	opcode := int32(0)

	opcode |= int32(pb.InsClass_InsClassRet & 0x07)

	opcode |= int32(srcType & 0x18)

	opcode |= int32(0x00 & 0xF0)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     0,
		Jf:     0,
		K:      k,
	}
}

func Misc(reg pb.Reg) *pb.Instruction {
	var k int32
	var oc int32
	switch reg {
	case pb.Reg_A:
		// TAX
		oc = int32(0x00)
		k = int32(pb.Reg_A)
	case pb.Reg_X:
		// TXA
		oc = int32(0x80)
		k = int32(pb.Reg_X)
	}
	opcode := int32(0)

	opcode |= int32(pb.InsClass_InsClassMisc & 0x07)

	opcode |= int32(0x00 & 0x08)

	opcode |= int32(oc & 0xF8)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     0,
		Jf:     0,
		K:      k,
	}
}

func Add[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluAdd, src)
}

func Sub[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluSub, src)
}

func Mul[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMul, src)
}

func Div[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluDiv, src)
}

func Or[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluOr, src)
}

func And[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluAnd, src)
}

func Lsh[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluLsh, src)
}

func Rsh[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluRsh, src)
}

func Neg[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluNeg, src)
}

func Mod[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMod, src)
}

func Xor[T Src](src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluXor, src)
}
