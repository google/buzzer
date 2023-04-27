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

func TestAluImmOperationCorrectEncoding(t *testing.T) {
	tests := []struct {
		testName string
		dstReg   uint8
		imm      int32
		op       uint8
		insClass uint8
		instrNo  uint32

		// The values for expected encoding are calculated manually by
		// following: http://shortn/_YhGoFtsPl9
		wantEnc []uint64

		// Check that the auxiliar functions that return the bytecode
		// directly have the values we expect.
		wantAuxFuncEncoding uint64
	}{
		{
			testName:            "Encoding Mov IMM 64",
			dstReg:              RegR0,
			imm:                 int32(-65535),
			op:                  AluMov,
			insClass:            InsClassAlu64,
			wantEnc:             []uint64{0xffff0001000000b8},
			wantAuxFuncEncoding: MovRegImm64(RegR0, int32(-65535)).GenerateBytecode()[0],
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			operation := NewAluImmOperation(AluMov, InsClassAlu64, tc.dstReg, tc.imm)
			if operation.DstReg != tc.dstReg {
				t.Fatalf("operation.dstReg = %d, want %d", operation.DstReg, tc.dstReg)
			}

			if operation.Operation != tc.op {
				t.Fatalf("operation.operation = %d, want %d", operation.Operation, tc.op)
			}

			if operation.InsClass != tc.insClass {
				t.Fatalf("operation.insClass = %d, want %d", operation.InsClass, tc.insClass)
			}

			if operation.Imm != tc.imm {
				t.Fatalf("operation.imm = %d, want %d", operation.Imm, tc.imm)
			}

			encodingArray := operation.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEnc) {
				t.Fatalf("operation.generateBytecode() = %x, want %x", encodingArray, tc.wantEnc)
			}

			// Maybe not all opcodes have an auxiliary function.
			if tc.wantAuxFuncEncoding != 0 {
				if encodingArray[0] != tc.wantAuxFuncEncoding {
					t.Fatalf("tc.wantAuxFuncEncoding =  %02x, want %02x", tc.wantAuxFuncEncoding, encodingArray[0])
				}
			}

			operation.NumerateInstruction(99)
			if operation.instructionNumber != 99 {
				t.Fatalf("operation.instructionNumber = %d, want 99", operation.instructionNumber)
			}
		})
	}
}

func TestAluRegOperationCorrectEncoding(t *testing.T) {
	tests := []struct {
		testName string
		dstReg   uint8
		srcReg   uint8
		op       uint8
		insClass uint8
		instrNo  uint32

		// The values for expected encoding are calculated manually by
		// following: http://shortn/_YhGoFtsPl9
		wantEnc uint64

		// Check that the auxiliar functions that return the bytecode
		// directly have the values we expect.
		wantAuxFuncEncoding uint64
	}{
		{
			testName:            "Encoding Mov IMM 64",
			dstReg:              RegR0,
			srcReg:              RegR1,
			op:                  AluMov,
			insClass:            InsClassAlu64,
			wantEnc:             0x10bf,
			wantAuxFuncEncoding: MovRegSrc64(RegR1, RegR0).GenerateBytecode()[0],
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			operation := NewAluRegOperation(AluMov, InsClassAlu64, tc.dstReg, tc.srcReg)
			if operation.DstReg != tc.dstReg {
				t.Fatalf("operation.dstReg = %d, want %d", operation.DstReg, tc.dstReg)
			}

			if operation.Operation != tc.op {
				t.Fatalf("operation.operation = %d, want %d", operation.Operation, tc.op)
			}

			if operation.InsClass != tc.insClass {
				t.Fatalf("operation.insClass = %d, want %d", operation.InsClass, tc.insClass)
			}

			if operation.SrcReg != tc.srcReg {
				t.Fatalf("operation.srcReg = %d, want %d", operation.SrcReg, tc.srcReg)
			}

			encodingArray := operation.GenerateBytecode()
			if len(encodingArray) != 1 {
				t.Fatalf("len(operation.generateBytecode()) = %d, want 1", len(encodingArray))
			}

			if encodingArray[0] != tc.wantEnc {
				t.Fatalf("encodingArray[0] = %02x want %02x", encodingArray[0], tc.wantEnc)
			}

			// Maybe not all opcodes have an auxiliary function.
			if tc.wantAuxFuncEncoding != 0 {
				if encodingArray[0] != tc.wantAuxFuncEncoding {
					t.Fatalf("encodingArray[0] =  %02x, want %02x", encodingArray[0], tc.wantAuxFuncEncoding)
				}
			}

			operation.NumerateInstruction(99)
			if operation.instructionNumber != 99 {
				t.Fatalf("operation.instructionNumber = %d, want 99", operation.instructionNumber)
			}
		})
	}
}
