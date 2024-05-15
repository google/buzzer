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
	protobuf "github.com/golang/protobuf/proto"
	"reflect"
	"testing"
)

func TestAluInstructionGenerationAndEncoding(t *testing.T) {
	testDstReg := pb.Reg_R9
	testSrcReg := pb.Reg_R7
	testImm := int32(-65535)
	tests := []struct {
		testName    string
		instruction *pb.Instruction

		wantDstReg           pb.Reg
		wantSrcReg           pb.Reg
		wantOffset           int32
		wantImm              int32
		wantInstructionClass pb.InsClass
		wantSrc              pb.SrcOperand
		wantOperationCode    pb.AluOperationCode

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:             "Encoding Add64 with immediate value as source",
			instruction:          Add64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAdd,
			wantEncoding:         []uint64{0xffff000100000907},
		},
		{
			testName:             "Encoding Add32 with immediate value as source",
			instruction:          Add(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAdd,
			wantEncoding:         []uint64{0xffff000100000904},
		},
		{
			testName:             "Encoding Sub64 with immediate value as source",
			instruction:          Sub64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluSub,
			wantEncoding:         []uint64{0xffff000100000917},
		},
		{
			testName:             "Encoding Sub32 with immediate value as source",
			instruction:          Sub(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluSub,
			wantEncoding:         []uint64{0xffff000100000914},
		},
		{
			testName:             "Encoding Mul64 with immediate value as source",
			instruction:          Mul64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMul,
			wantEncoding:         []uint64{0xffff000100000927},
		},
		{
			testName:             "Encoding Mul32 with immediate value as source",
			instruction:          Mul(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMul,
			wantEncoding:         []uint64{0xffff000100000924},
		},
		{
			testName:             "Encoding Div64 with immediate value as source",
			instruction:          Div64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluDiv,
			wantEncoding:         []uint64{0xffff000100000937},
		},
		{
			testName:             "Encoding Div32 with immediate value as source",
			instruction:          Div(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluDiv,
			wantEncoding:         []uint64{0xffff000100000934},
		},
		{
			testName:             "Encoding Or64 with immediate value as source",
			instruction:          Or64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluOr,
			wantEncoding:         []uint64{0xffff000100000947},
		},
		{
			testName:             "Encoding Or32 with immediate value as source",
			instruction:          Or(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluOr,
			wantEncoding:         []uint64{0xffff000100000944},
		},
		{
			testName:             "Encoding And64 with immediate value as source",
			instruction:          And64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAnd,
			wantEncoding:         []uint64{0xffff000100000957},
		},
		{
			testName:             "Encoding And32 with immediate value as source",
			instruction:          And(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAnd,
			wantEncoding:         []uint64{0xffff000100000954},
		},
		{
			testName:             "Encoding Lsh64 with immediate value as source",
			instruction:          Lsh64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluLsh,
			wantEncoding:         []uint64{0xffff000100000967},
		},
		{
			testName:             "Encoding Lsh32 with immediate value as source",
			instruction:          Lsh(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluLsh,
			wantEncoding:         []uint64{0xffff000100000964},
		},
		{
			testName:             "Encoding Rsh64 with immediate value as source",
			instruction:          Rsh64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluRsh,
			wantEncoding:         []uint64{0xffff000100000977},
		},
		{
			testName:             "Encoding Rsh32 with immediate value as source",
			instruction:          Rsh(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluRsh,
			wantEncoding:         []uint64{0xffff000100000974},
		},
		{
			testName:             "Encoding Neg64 with immediate value as source",
			instruction:          Neg64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluNeg,
			wantEncoding:         []uint64{0xffff000100000987},
		},
		{
			testName:             "Encoding Neg32 with immediate value as source",
			instruction:          Neg(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluNeg,
			wantEncoding:         []uint64{0xffff000100000984},
		},
		{
			testName:             "Encoding Mod64 with immediate value as source",
			instruction:          Mod64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMod,
			wantEncoding:         []uint64{0xffff000100000997},
		},
		{
			testName:             "Encoding Mod32 with immediate value as source",
			instruction:          Mod(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMod,
			wantEncoding:         []uint64{0xffff000100000994},
		},
		{
			testName:             "Encoding Xor64 with immediate value as source",
			instruction:          Xor64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluXor,
			wantEncoding:         []uint64{0xffff0001000009a7},
		},
		{
			testName:             "Encoding Xor32 with immediate value as source",
			instruction:          Xor(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluXor,
			wantEncoding:         []uint64{0xffff0001000009a4},
		},
		{
			testName:             "Encoding Mov64 with immediate value as source",
			instruction:          Mov64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMov,
			wantEncoding:         []uint64{0xffff0001000009b7},
		},
		{
			testName:             "Encoding Mov32 with immediate value as source",
			instruction:          Mov(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMov,
			wantEncoding:         []uint64{0xffff0001000009b4},
		},
		{
			testName:             "Encoding Arsh64 with immediate value as source",
			instruction:          Arsh64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluArsh,
			wantEncoding:         []uint64{0xffff0001000009c7},
		},
		{
			testName:             "Encoding Arsh32 with immediate value as source",
			instruction:          Arsh(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluArsh,
			wantEncoding:         []uint64{0xffff0001000009c4},
		},
		{
			testName:             "Encoding End64 with immediate value as source",
			instruction:          End64(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluEnd,
			wantEncoding:         []uint64{0xffff0001000009d7},
		},
		{
			testName:             "Encoding End32 with immediate value as source",
			instruction:          End(testDstReg, testImm),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantSrcReg:           pb.Reg_R0,
			wantSrc:              pb.SrcOperand_Immediate,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluEnd,
			wantEncoding:         []uint64{0xffff0001000009d4},
		},
		{
			testName:             "Encoding Add64 with register value as source",
			instruction:          Add64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAdd,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x790f},
		},
		{
			testName:             "Encoding Add32 with register value as source",
			instruction:          Add(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAdd,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x790c},
		},
		{
			testName:             "Encoding Sub64 with register value as source",
			instruction:          Sub64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluSub,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x791f},
		},
		{
			testName:             "Encoding Sub32 with register value as source",
			instruction:          Sub(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluSub,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x791c},
		},
		{
			testName:             "Encoding Mul64 with register value as source",
			instruction:          Mul64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMul,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x792f},
		},
		{
			testName:             "Encoding Mul32 with register value as source",
			instruction:          Mul(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMul,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x792c},
		},
		{
			testName:             "Encoding Div64 with register value as source",
			instruction:          Div64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluDiv,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x793f},
		},
		{
			testName:             "Encoding Div32 with register value as source",
			instruction:          Div(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluDiv,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x793c},
		},
		{
			testName:             "Encoding Or64 with register value as source",
			instruction:          Or64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluOr,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x794f},
		},
		{
			testName:             "Encoding Or32 with register value as source",
			instruction:          Or(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluOr,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x794c},
		},
		{
			testName:             "Encoding And64 with register value as source",
			instruction:          And64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAnd,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x795f},
		},
		{
			testName:             "Encoding And32 with register value as source",
			instruction:          And(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluAnd,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x795c},
		},
		{
			testName:             "Encoding Lsh64 with register value as source",
			instruction:          Lsh64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluLsh,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x796f},
		},
		{
			testName:             "Encoding Lsh32 with register value as source",
			instruction:          Lsh(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluLsh,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x796c},
		},
		{
			testName:             "Encoding Rsh64 with register value as source",
			instruction:          Rsh64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluRsh,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x797f},
		},
		{
			testName:             "Encoding Rsh32 with register value as source",
			instruction:          Rsh(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluRsh,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x797c},
		},
		{
			testName:             "Encoding Neg64 with register value as source",
			instruction:          Neg64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluNeg,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x798f},
		},
		{
			testName:             "Encoding Neg32 with register value as source",
			instruction:          Neg(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluNeg,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x798c},
		},
		{
			testName:             "Encoding Mod64 with register value as source",
			instruction:          Mod64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMod,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x799f},
		},
		{
			testName:             "Encoding Mod32 with register value as source",
			instruction:          Mod(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMod,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x799c},
		},
		{
			testName:             "Encoding Xor64 with register value as source",
			instruction:          Xor64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluXor,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x79af},
		},
		{
			testName:             "Encoding Xor32 with register value as source",
			instruction:          Xor(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluXor,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x79ac},
		},
		{
			testName:             "Encoding Mov64 with register value as source",
			instruction:          Mov64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMov,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x79bf},
		},
		{
			testName:             "Encoding Mov32 with register value as source",
			instruction:          Mov(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluMov,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x79bc},
		},
		{
			testName:             "Encoding Arsh64 with register value as source",
			instruction:          Arsh64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluArsh,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x79cf},
		},
		{
			testName:             "Encoding Arsh32 with register value as source",
			instruction:          Arsh(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluArsh,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x79cc},
		},
		{
			testName:             "Encoding End64 with register value as source",
			instruction:          End64(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluEnd,
			wantInstructionClass: pb.InsClass_InsClassAlu64,
			wantEncoding:         []uint64{0x79df},
		},
		{
			testName:             "Encoding End32 with register value as source",
			instruction:          End(testDstReg, testSrcReg),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantOffset:           0,
			wantOperationCode:    pb.AluOperationCode_AluEnd,
			wantInstructionClass: pb.InsClass_InsClassAlu,
			wantEncoding:         []uint64{0x79dc},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction := tc.instruction
			var opcode *pb.AluJmpOpcode
			switch o := instruction.Opcode.(type) {
			case *pb.Instruction_AlujmpOpcode:
				opcode = o.AlujmpOpcode
			default:
				t.Fatalf("could not convert opcode to alu type, proto: %s", protobuf.MarshalTextString(instruction))

			}

			var operationCode pb.AluOperationCode
			switch o := opcode.OperationCode.(type) {
			case *pb.AluJmpOpcode_AluOpcode:
				operationCode = o.AluOpcode
			default:
				t.Fatalf("could not convert operation code to alu type, proto: %s", protobuf.MarshalTextString(opcode))
			}

			t.Logf("Running test case %s", tc.testName)
			if instruction.DstReg != tc.wantDstReg {
				t.Fatalf("instruction.dstReg = %d, want %d", instruction.DstReg, tc.wantDstReg)
			}

			if instruction.SrcReg != tc.wantSrcReg {
				t.Fatalf("instruction.srcReg = %d, want %d", instruction.SrcReg, tc.wantSrcReg)
			}

			if instruction.Offset != tc.wantOffset {
				t.Fatalf("instruction.dstReg = %d, want %d", instruction.Offset, tc.wantOffset)
			}

			if instruction.Immediate != tc.wantImm {
				t.Fatalf("instruction.Immediate = %d, want %d", instruction.Immediate, tc.wantImm)
			}

			if opcode.Source != tc.wantSrc {
				t.Fatalf("opcode.Src = %d, want %d", opcode.Source, tc.wantSrc)
			}

			if opcode.InstructionClass != tc.wantInstructionClass {
				t.Fatalf("opcode.InstructionClass = %d, want %d", opcode.InstructionClass, tc.wantInstructionClass)
			}

			if operationCode != tc.wantOperationCode {
				t.Fatalf("operationCode = %d, want %d", operationCode, tc.wantOperationCode)
			}

			encodingArray, err := encodeInstruction(instruction)
			if err != nil {
				t.Fatalf("unexpected error when ecoding: %v", err)
			}
			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Fatalf("instruction.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}
		})
	}
}
