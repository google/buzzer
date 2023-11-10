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
	"reflect"
	"testing"
)

func TestImmJmpOperationCorrectEncoding(t *testing.T) {
	testDstReg := RegR9
	testImm := int32(42)
	testOffset := int16(10)
	tests := []struct {
		testName    string
		instruction Instruction

		wantOpcode uint8
		wantClass  uint8
		wantDstReg *Register
		wantImm    int32
		wantOffset int16

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:     "Encoding Jmp",
			instruction:  Jmp(42),
			wantDstReg:   RegR0,
			wantImm:      UnusedField,
			wantOpcode:   JmpJA,
			wantClass:    InsClassJmp,
			wantOffset:   42,
			wantEncoding: []uint64{0x2a0005},
		},
		{
			testName:     "Encoding Exit",
			instruction:  Exit(),
			wantDstReg:   RegR0,
			wantImm:      UnusedField,
			wantOpcode:   JmpExit,
			wantClass:    InsClassJmp,
			wantOffset:   UnusedField,
			wantEncoding: []uint64{0x95},
		},
		{
			testName:     "Encoding JEQ",
			instruction:  JmpEQ(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJEQ,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0915},
		},
		{
			testName:     "Encoding JGE",
			instruction:  JmpGE(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJGE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0935},
		},
		{
			testName:     "Encoding JNE",
			instruction:  JmpNE(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJNE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0955},
		},
		{
			testName:     "Encoding JSGE",
			instruction:  JmpSGE(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJSGE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0975},
		},
		{
			testName:     "Encoding JLE",
			instruction:  JmpLE(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJLE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a09b5},
		},
		{
			testName:     "Encoding JSLE",
			instruction:  JmpSLE(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJSLE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a09d5},
		},
		{
			testName:     "Encoding JGT",
			instruction:  JmpGT(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJGT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0925},
		},
		{
			testName:     "Encoding JSET",
			instruction:  JmpSET(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJSET,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0945},
		},
		{
			testName:     "Encoding JSGT",
			instruction:  JmpSGT(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJSGT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a0965},
		},
		{
			testName:     "Encoding JLT",
			instruction:  JmpLT(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJLT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a09a5},
		},
		{
			testName:     "Encoding JSLT",
			instruction:  JmpSLT(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJSLT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0x2a000a09c5},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction, ok := tc.instruction.(*JmpImmInstruction)
			if !ok {
				t.Fatalf("Could not cast instruction to JmpImm %v", tc.instruction)
			}
			t.Logf("Running test case %s", tc.testName)
			if instruction.DstReg != tc.wantDstReg {
				t.Fatalf("instruction.dstReg = %d, want %d", instruction.DstReg, tc.wantDstReg)
			}

			if instruction.Opcode != tc.wantOpcode {
				t.Fatalf("instruction.operation = %d, want %d", instruction.Opcode, tc.wantOpcode)
			}

			if instruction.InstructionClass != tc.wantClass {
				t.Fatalf("instruction.insClass = %d, want %d", instruction.InstructionClass, tc.wantClass)
			}

			if instruction.Imm != tc.wantImm {
				t.Fatalf("instruction.imm = %d, want %d", instruction.Imm, tc.wantImm)
			}

			if instruction.Offset != tc.wantOffset {
				t.Fatalf("instruction.FalseBranchSize = %d, want %d", instruction.Offset, tc.wantOffset)
			}

			encodingArray := instruction.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Fatalf("instruction.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}

		})
	}
}

func TestRegJmpOperationCorrectEncoding(t *testing.T) {
	testDstReg := RegR9
	testSrcReg := RegR0
	testOffset := int16(10)
	tests := []struct {
		testName    string
		instruction Instruction

		wantOpcode uint8
		wantClass  uint8
		wantDstReg *Register
		wantSrcReg *Register
		wantOffset int16

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:     "Encoding JEQ",
			instruction:  JmpEQ(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJEQ,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa091d},
		},
		{
			testName:     "Encoding JGE",
			instruction:  JmpGE(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJGE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa093d},
		},
		{
			testName:     "Encoding JNE",
			instruction:  JmpNE(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJNE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa095d},
		},
		{
			testName:     "Encoding JSGE",
			instruction:  JmpSGE(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJSGE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa097d},
		},
		{
			testName:     "Encoding JLE",
			instruction:  JmpLE(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJLE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa09bd},
		},
		{
			testName:     "Encoding JSLE",
			instruction:  JmpSLE(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJSLE,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa09dd},
		},
		{
			testName:     "Encoding JGT",
			instruction:  JmpGT(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJGT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa092d},
		},
		{
			testName:     "Encoding JSET",
			instruction:  JmpSET(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJSET,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa094d},
		},
		{
			testName:     "Encoding JSGT",
			instruction:  JmpSGT(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJSGT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa096d},
		},
		{
			testName:     "Encoding JLT",
			instruction:  JmpLT(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJLT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa09ad},
		},
		{
			testName:     "Encoding JSLT",
			instruction:  JmpSLT(testDstReg, testSrcReg, testOffset),
			wantDstReg:   testDstReg,
			wantSrcReg:	  testSrcReg,
			wantOpcode:   JmpJSLT,
			wantClass:    InsClassJmp,
			wantOffset:   testOffset,
			wantEncoding: []uint64{0xa09cd},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction, ok := tc.instruction.(*JmpRegInstruction)
			if !ok {
				t.Fatalf("Could not cast instruction to JmpImm %v", tc.instruction)
			}
			t.Logf("Running test case %s", tc.testName)
			if instruction.DstReg != tc.wantDstReg {
				t.Fatalf("instruction.dstReg = %d, want %d", instruction.DstReg, tc.wantDstReg)
			}

			if instruction.Opcode != tc.wantOpcode {
				t.Fatalf("instruction.operation = %d, want %d", instruction.Opcode, tc.wantOpcode)
			}

			if instruction.InstructionClass != tc.wantClass {
				t.Fatalf("instruction.insClass = %d, want %d", instruction.InstructionClass, tc.wantClass)
			}

			if instruction.SrcReg != tc.wantSrcReg {
				t.Fatalf("instruction.srcReg = %d, want %d", instruction.SrcReg, tc.wantSrcReg)
			}

			if instruction.Offset != tc.wantOffset {
				t.Fatalf("instruction.FalseBranchSize = %d, want %d", instruction.Offset, tc.wantOffset)
			}

			encodingArray := instruction.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Fatalf("instruction.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}

		})
	}
}
