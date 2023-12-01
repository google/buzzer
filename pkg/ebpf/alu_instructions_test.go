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

func TestAluImmInstructionGenerationAndEncoding(t *testing.T) {
	testReg := RegR9
	testImm := int32(-65535)
	tests := []struct {
		testName    string
		instruction Instruction

		wantOpcode uint8
		wantClass  uint8
		wantDstReg *Register
		wantImm    int32

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:     "Encoding Add64",
			instruction:  Add64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluAdd,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000907},
		},
		{
			testName:     "Encoding Add32",
			instruction:  Add(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluAdd,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000904},
		},
		{
			testName:     "Encoding Sub64",
			instruction:  Sub64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluSub,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000917},
		},
		{
			testName:     "Encoding Sub32",
			instruction:  Sub(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluSub,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000914},
		},
		{
			testName:     "Encoding Mul64",
			instruction:  Mul64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluMul,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000927},
		},
		{
			testName:     "Encoding Mul32",
			instruction:  Mul(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluMul,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000924},
		},
		{
			testName:     "Encoding Div64",
			instruction:  Div64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluDiv,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000937},
		},
		{
			testName:     "Encoding Div32",
			instruction:  Div(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluDiv,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000934},
		},
		{
			testName:     "Encoding Or64",
			instruction:  Or64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluOr,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000947},
		},
		{
			testName:     "Encoding Or32",
			instruction:  Or(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluOr,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000944},
		},
		{
			testName:     "Encoding And64",
			instruction:  And64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluAnd,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000957},
		},
		{
			testName:     "Encoding And32",
			instruction:  And(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluAnd,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000954},
		},
		{
			testName:     "Encoding Lsh64",
			instruction:  Lsh64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluLsh,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000967},
		},
		{
			testName:     "Encoding Lsh32",
			instruction:  Lsh(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluLsh,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000964},
		},
		{
			testName:     "Encoding Rsh64",
			instruction:  Rsh64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluRsh,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000977},
		},
		{
			testName:     "Encoding Rsh32",
			instruction:  Rsh(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluRsh,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000974},
		},
		{
			testName:     "Encoding Neg64",
			instruction:  Neg64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluNeg,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000987},
		},
		{
			testName:     "Encoding Neg32",
			instruction:  Neg(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluNeg,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000984},
		},
		{
			testName:     "Encoding Mod64",
			instruction:  Mod64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluMod,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff000100000997},
		},
		{
			testName:     "Encoding Mod32",
			instruction:  Mod(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluMod,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff000100000994},
		},
		{
			testName:     "Encoding Xor64",
			instruction:  Xor64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluXor,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff0001000009a7},
		},
		{
			testName:     "Encoding Xor32",
			instruction:  Xor(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluXor,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff0001000009a4},
		},
		{
			testName:     "Encoding Mov64",
			instruction:  Mov64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluMov,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff0001000009b7},
		},
		{
			testName:     "Encoding Mov32",
			instruction:  Mov(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluMov,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff0001000009b4},
		},
		{
			testName:     "Encoding Arsh64",
			instruction:  Arsh64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluArsh,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff0001000009c7},
		},
		{
			testName:     "Encoding Arsh32",
			instruction:  Arsh(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluArsh,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff0001000009c4},
		},
		{
			testName:     "Encoding End64",
			instruction:  End64(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluEnd,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0xffff0001000009d7},
		},
		{
			testName:     "Encoding End32",
			instruction:  End(testReg, testImm),
			wantDstReg:   testReg,
			wantImm:      testImm,
			wantOpcode:   AluEnd,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0xffff0001000009d4},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction, ok := tc.instruction.(*AluImmInstruction)
			if !ok {
				t.Fatal("Could not cas instruction to AluImm")
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

			encodingArray := instruction.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Fatalf("instruction.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}
		})
	}
}

func TestAluRegOperationCorrectEncoding(t *testing.T) {
	tests := []struct {
		testName    string
		instruction Instruction

		wantOpcode uint8
		wantClass  uint8
		wantDstReg *Register
		wantSrcReg *Register

		// The values for expected encoding are calculated manually
		wantEncoding []uint64
	}{
		{
			testName:     "Encoding Add64",
			instruction:  Add64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluAdd,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x790f},
		},
		{
			testName:     "Encoding Add32",
			instruction:  Add(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluAdd,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x790c},
		},
		{
			testName:     "Encoding Sub64",
			instruction:  Sub64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluSub,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x791f},
		},
		{
			testName:     "Encoding Sub32",
			instruction:  Sub(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluSub,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x791c},
		},
		{
			testName:     "Encoding Mul64",
			instruction:  Mul64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluMul,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x792f},
		},
		{
			testName:     "Encoding Mul32",
			instruction:  Mul(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluMul,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x792c},
		},
		{
			testName:     "Encoding Div64",
			instruction:  Div64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluDiv,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x793f},
		},
		{
			testName:     "Encoding Div32",
			instruction:  Div(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluDiv,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x793c},
		},
		{
			testName:     "Encoding Or64",
			instruction:  Or64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluOr,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x794f},
		},
		{
			testName:     "Encoding Or32",
			instruction:  Or(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluOr,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x794c},
		},
		{
			testName:     "Encoding And64",
			instruction:  And64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluAnd,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x795f},
		},
		{
			testName:     "Encoding And32",
			instruction:  And(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluAnd,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x795c},
		},
		{
			testName:     "Encoding Lsh64",
			instruction:  Lsh64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluLsh,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x796f},
		},
		{
			testName:     "Encoding Lsh32",
			instruction:  Lsh(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluLsh,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x796c},
		},
		{
			testName:     "Encoding Rsh64",
			instruction:  Rsh64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluRsh,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x797f},
		},
		{
			testName:     "Encoding Rsh32",
			instruction:  Rsh(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluRsh,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x797c},
		},
		{
			testName:     "Encoding Neg64",
			instruction:  Neg64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluNeg,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x798f},
		},
		{
			testName:     "Encoding Neg32",
			instruction:  Neg(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluNeg,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x798c},
		},
		{
			testName:     "Encoding Mod64",
			instruction:  Mod64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluMod,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x799f},
		},
		{
			testName:     "Encoding Mod32",
			instruction:  Mod(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluMod,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x799c},
		},
		{
			testName:     "Encoding Xor64",
			instruction:  Xor64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluXor,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x79af},
		},
		{
			testName:     "Encoding Xor32",
			instruction:  Xor(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluXor,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x79ac},
		},
		{
			testName:     "Encoding Mov64",
			instruction:  Mov64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluMov,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x79bf},
		},
		{
			testName:     "Encoding Mov32",
			instruction:  Mov(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluMov,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x79bc},
		},
		{
			testName:     "Encoding Arsh64",
			instruction:  Arsh64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluArsh,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x79cf},
		},
		{
			testName:     "Encoding Arsh32",
			instruction:  Arsh(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluArsh,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x79cc},
		},
		{
			testName:     "Encoding End64",
			instruction:  End64(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluEnd,
			wantClass:    InsClassAlu64,
			wantEncoding: []uint64{0x79df},
		},
		{
			testName:     "Encoding End32",
			instruction:  End(RegR9, RegR7),
			wantDstReg:   RegR9,
			wantSrcReg:   RegR7,
			wantOpcode:   AluEnd,
			wantClass:    InsClassAlu,
			wantEncoding: []uint64{0x79dc},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction, ok := tc.instruction.(*AluRegInstruction)
			if !ok {
				t.Fatal("Could not cas instruction to AluReg")
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

			encodingArray := instruction.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Fatalf("instruction.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}
		})
	}
}
