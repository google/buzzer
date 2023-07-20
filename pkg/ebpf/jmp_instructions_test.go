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
		wantOffset	  int16

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
			wantOffset:	  42,
			wantEncoding: []uint64{0x2a0005},
		},
		{
			testName:     "Encoding Exit",
			instruction:  Exit(),
			wantDstReg:   RegR0,
			wantImm:      UnusedField,
			wantOpcode:   JmpExit,
			wantClass:    InsClassJmp,
			wantOffset:	  UnusedField,
			wantEncoding: []uint64{0x95},
		},
		{
			testName:     "Encoding JEQ",
			instruction:  JmpEQ(testDstReg, testImm, testOffset),
			wantDstReg:   testDstReg,
			wantImm:      testImm,
			wantOpcode:   JmpJEQ,
			wantClass:    InsClassJmp,
			wantOffset:	  testOffset,
			wantEncoding: []uint64{0x95},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction, ok := tc.instruction.(*JmpImmInstruction)
			if !ok {
				t.Fatalf("Could not cas instruction to JmpImm %v", tc.instruction)
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

			if instruction.FalseBranchSize != tc.wantOffset {
				t.Fatalf("instruction.FalseBranchSize = %d, want %d", instruction.FalseBranchSize, tc.wantOffset)
			}

			encodingArray := instruction.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEncoding) {
				t.Fatalf("instruction.generateBytecode() = %x, want %x", encodingArray, tc.wantEncoding)
			}

			instruction.NumerateInstruction(99)
			if instruction.instructionNumber != 99 {
				t.Fatalf("instruction.instructionNumber = %d, want 99", instruction.instructionNumber)
			}
		})
	}
}
