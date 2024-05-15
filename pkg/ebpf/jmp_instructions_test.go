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

func TestJmpOperationCorrectEncoding(t *testing.T) {
	testDstReg := pb.Reg_R9
	testSrcReg := pb.Reg_R0
	testImm := int32(42)
	testOffset := int16(10)
	tests := []struct {
		testName    string
		instruction *pb.Instruction

		wantDstReg           pb.Reg
		wantSrcReg           pb.Reg
		wantOffset           int16
		wantImm              int32
		wantInstructionClass pb.InsClass
		wantSrc              pb.SrcOperand
		wantOperationCode    pb.JmpOperationCode

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:             "Encoding Jmp",
			instruction:          Jmp(42),
			wantDstReg:           UnusedField,
			wantImm:              UnusedField,
			wantOperationCode:    pb.JmpOperationCode_JmpJA,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           42,
			wantEncoding:         []uint64{0x2a0005},
		},
		{
			testName:             "Encoding Exit",
			instruction:          Exit(),
			wantDstReg:           UnusedField,
			wantImm:              UnusedField,
			wantOperationCode:    pb.JmpOperationCode_JmpExit,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           UnusedField,
			wantEncoding:         []uint64{0x95},
		},
		{
			testName:             "Encoding JEQ",
			instruction:          JmpEQ(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJEQ,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0915},
		},
		{
			testName:             "Encoding JGE",
			instruction:          JmpGE(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJGE,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0935},
		},
		{
			testName:             "Encoding JNE",
			instruction:          JmpNE(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJNE,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0955},
		},
		{
			testName:             "Encoding JSGE",
			instruction:          JmpSGE(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJSGE,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0975},
		},
		{
			testName:             "Encoding JLE",
			instruction:          JmpLE(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJLE,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a09b5},
		},
		{
			testName:             "Encoding JSLE",
			instruction:          JmpSLE(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJSLE,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a09d5},
		},
		{
			testName:             "Encoding JGT",
			instruction:          JmpGT(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJGT,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0925},
		},
		{
			testName:             "Encoding JSET",
			instruction:          JmpSET(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJSET,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0945},
		},
		{
			testName:             "Encoding JSGT",
			instruction:          JmpSGT(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJSGT,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a0965},
		},
		{
			testName:             "Encoding JLT",
			instruction:          JmpLT(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJLT,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a09a5},
		},
		{
			testName:             "Encoding JSLT",
			instruction:          JmpSLT(testDstReg, testImm, testOffset),
			wantDstReg:           testDstReg,
			wantImm:              testImm,
			wantOperationCode:    pb.JmpOperationCode_JmpJSLT,
			wantSrc:              pb.SrcOperand_Immediate,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0x2a000a09c5},
		},
		{
			testName:             "Encoding JEQ with source register",
			instruction:          JmpEQ(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJEQ,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa091d},
		},
		{
			testName:             "Encoding JGE with source register",
			instruction:          JmpGE(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJGE,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa093d},
		},
		{
			testName:             "Encoding JNE with source register",
			instruction:          JmpNE(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJNE,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa095d},
		},
		{
			testName:             "Encoding JSGE with source register",
			instruction:          JmpSGE(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJSGE,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa097d},
		},
		{
			testName:             "Encoding JLE with source register",
			instruction:          JmpLE(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJLE,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa09bd},
		},
		{
			testName:             "Encoding JSLE with source register",
			instruction:          JmpSLE(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJSLE,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa09dd},
		},
		{
			testName:             "Encoding JGT with source register",
			instruction:          JmpGT(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJGT,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa092d},
		},
		{
			testName:             "Encoding JSET with source register",
			instruction:          JmpSET(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJSET,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa094d},
		},
		{
			testName:             "Encoding JSGT with source register",
			instruction:          JmpSGT(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJSGT,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa096d},
		},
		{
			testName:             "Encoding JLT with source register",
			instruction:          JmpLT(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJLT,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa09ad},
		},
		{
			testName:             "Encoding JSLT with source register",
			instruction:          JmpSLT(testDstReg, testSrcReg, testOffset),
			wantDstReg:           testDstReg,
			wantSrcReg:           testSrcReg,
			wantOperationCode:    pb.JmpOperationCode_JmpJSLT,
			wantSrc:              pb.SrcOperand_RegSrc,
			wantInstructionClass: pb.InsClass_InsClassJmp,
			wantOffset:           testOffset,
			wantEncoding:         []uint64{0xa09cd},
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
				t.Fatalf("could not convert opcode to jmp type, proto: %s", protobuf.MarshalTextString(instruction))

			}

			var operationCode pb.JmpOperationCode
			switch o := opcode.OperationCode.(type) {
			case *pb.AluJmpOpcode_JmpOpcode:
				operationCode = o.JmpOpcode
			default:
				t.Fatalf("could not convert operation code to jmp type, proto: %s", protobuf.MarshalTextString(opcode))
			}

			t.Logf("Running test case %s", tc.testName)
			if instruction.DstReg != tc.wantDstReg {
				t.Fatalf("instruction.dstReg = %d, want %d", instruction.DstReg, tc.wantDstReg)
			}

			if instruction.SrcReg != tc.wantSrcReg {
				t.Fatalf("instruction.srcReg = %d, want %d", instruction.SrcReg, tc.wantSrcReg)
			}

			if instruction.Offset != int32(tc.wantOffset) {
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
