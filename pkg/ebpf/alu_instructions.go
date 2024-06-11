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

func newAluInstruction[T Src](oc pb.AluOperationCode, insclass pb.InsClass, dst pb.Reg, src T) *pb.Instruction {
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
    case int64:
        upper := int32(src >> 32)
		return &pb.Instruction{
			Opcode: &pb.Instruction_MemOpcode{
				MemOpcode: &pb.MemOpcode {
					Mode:			pb.StLdMode_StLdModeIMM,
					Size:			pb.StLdSize_StLdSizeDW,
					InstructionClass:	pb.InsClass_InsClassLd,
				},
			},
			DstReg:		pb.Reg_R0,
			SrcReg:		pb.Reg_R0,
			Offset:		0,
			Immediate:	int32(src),
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
		          Immediate: upper,
		          PseudoInstruction: &pb.Instruction_Empty{
			         Empty: &pb.Empty{},
		          },
               },
            },
        }
    default:
		srcType = pb.SrcOperand_Immediate
		srcReg = pb.Reg_R0
		imm = any(src).(int32)
	}

	return &pb.Instruction{
		Opcode: &pb.Instruction_AluOpcode{
			AluOpcode: &pb.AluOpcode{
				OperationCode:    oc,
				Source:           srcType,
				InstructionClass: insclass,
            },
        },
		DstReg:    dst,
		SrcReg:    srcReg,
		Offset:    0,
		Immediate: imm,
		PseudoInstruction: &pb.Instruction_Empty{
			Empty: &pb.Empty{},
		},
	}
}

// Add64 Creates a new 64 bit Add instruction that is either imm or reg depending
// on the data type of src
func Add64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluAdd, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Add Creates a new 32 bit Add instruction that is either imm or reg depending
// on the data type of src
func Add[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluAdd, pb.InsClass_InsClassAlu, dstReg, src)
}

// Sub64 Creates a new 64 bit Sub instruction that is either imm or reg depending
// on the data type of src
func Sub64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluSub, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Sub Creates a new 32 bit Sub instruction that is either imm or reg depending
// on the data type of src
func Sub[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluSub, pb.InsClass_InsClassAlu, dstReg, src)
}

// Mul64 Creates a new 64 bit Mul instruction that is either imm or reg depending
// on the data type of src
func Mul64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMul, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Mul Creates a new 32 bit Mul instruction that is either imm or reg depending
// on the data type of src
func Mul[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMul, pb.InsClass_InsClassAlu, dstReg, src)
}

// Div64 Creates a new 64 bit Div instruction that is either imm or reg depending
// on the data type of src
func Div64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluDiv, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Div Creates a new 32 bit Div instruction that is either imm or reg depending
// on the data type of src
func Div[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluDiv, pb.InsClass_InsClassAlu, dstReg, src)
}

// Or64 Creates a new 64 bit Or instruction that is either imm or reg depending
// on the data type of src
func Or64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluOr, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Or Creates a new 32 bit Or instruction that is either imm or reg depending
// on the data type of src
func Or[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluOr, pb.InsClass_InsClassAlu, dstReg, src)
}

// And64 Creates a new 64 bit And instruction that is either imm or reg depending
// on the data type of src
func And64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluAnd, pb.InsClass_InsClassAlu64, dstReg, src)
}

// And Creates a new 32 bit And instruction that is either imm or reg depending
// on the data type of src
func And[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluAnd, pb.InsClass_InsClassAlu, dstReg, src)
}

// Lsh64 Creates a new 64 bit Lsh instruction that is either imm or reg depending
// on the data type of src
func Lsh64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluLsh, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Lsh Creates a new 32 bit Lsh instruction that is either imm or reg depending
// on the data type of src
func Lsh[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluLsh, pb.InsClass_InsClassAlu, dstReg, src)
}

// Rsh64 Creates a new 64 bit Rsh instruction that is either imm or reg depending
// on the data type of src
func Rsh64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluRsh, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Rsh Creates a new 32 bit Rsh instruction that is either imm or reg depending
// on the data type of src
func Rsh[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluRsh, pb.InsClass_InsClassAlu, dstReg, src)
}

// Neg64 Creates a new 64 bit Neg instruction that is either imm or reg depending
// on the data type of src
func Neg64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluNeg, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Neg Creates a new 32 bit Neg instruction that is either imm or reg depending
// on the data type of src
func Neg[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluNeg, pb.InsClass_InsClassAlu, dstReg, src)
}

// Mod64 Creates a new 64 bit Mod instruction that is either imm or reg depending
// on the data type of src
func Mod64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMod, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Mod Creates a new 32 bit Mod instruction that is either imm or reg depending
// on the data type of src
func Mod[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMod, pb.InsClass_InsClassAlu, dstReg, src)
}

// Xor64 Creates a new 64 bit Xor instruction that is either imm or reg depending
// on the data type of src
func Xor64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluXor, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Xor Creates a new 32 bit Xor instruction that is either imm or reg depending
// on the data type of src
func Xor[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluXor, pb.InsClass_InsClassAlu, dstReg, src)
}

// Mov64 Creates a new 64 bit Mov instruction that is either imm or reg depending
// on the data type of src
func Mov64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMov, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Mov Creates a new 32 bit Mov instruction that is either imm or reg depending
// on the data type of src
func Mov[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluMov, pb.InsClass_InsClassAlu, dstReg, src)
}

// Arsh64 Creates a new 64 bit Arsh instruction that is either imm or reg depending
// on the data type of src
func Arsh64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluArsh, pb.InsClass_InsClassAlu64, dstReg, src)
}

// Arsh Creates a new 32 bit Arsh instruction that is either imm or reg depending
// on the data type of src
func Arsh[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluArsh, pb.InsClass_InsClassAlu, dstReg, src)
}

// End64 Creates a new 64 bit End instruction that is either imm or reg depending
// on the data type of src
func End64[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluEnd, pb.InsClass_InsClassAlu64, dstReg, src)
}

// End Creates a new 32 bit End instruction that is either imm or reg depending
// on the data type of src
func End[T Src](dstReg pb.Reg, src T) *pb.Instruction {
	return newAluInstruction(pb.AluOperationCode_AluEnd, pb.InsClass_InsClassAlu, dstReg, src)
}
