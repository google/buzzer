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

func TestJmpOperationCorrectEncoding(t *testing.T) {
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
			testName:            "Imm jump operation",
			dstReg:              RegR0,
			imm:                 int32(1),
			op:                  JmpJA,
			insClass:            InsClassAlu64,
			wantEnc:             []uint64{0x100000007},
			wantAuxFuncEncoding: GuardJump(JmpJA, InsClassAlu64, RegR0, 1).GenerateBytecode()[0],
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			operation := GuardJump(tc.op, tc.insClass, tc.dstReg, tc.imm)
			if operation.DstReg != tc.dstReg {
				t.Errorf("operation.dstReg = %d, want %d", operation.DstReg, tc.dstReg)
			}

			if operation.Instruction != tc.op {
				t.Errorf("operation.operation = %d, want %d", operation.Instruction, tc.op)
			}

			if operation.InsClass != tc.insClass {
				t.Errorf("operation.insClass = %d, want %d", operation.InsClass, tc.insClass)
			}

			if operation.Imm != tc.imm {
				t.Errorf("operation.imm = %d, want %d", operation.Imm, tc.imm)
			}

			encodingArray := operation.GenerateBytecode()
			if !reflect.DeepEqual(encodingArray, tc.wantEnc) {
				t.Fatalf("operation.generateBytecode() = %v, want %v", encodingArray, tc.wantEnc)
			}

			// Maybe not all opcodes have an auxiliary function.
			if tc.wantAuxFuncEncoding != 0 {
				if encodingArray[0] != tc.wantAuxFuncEncoding {
					t.Errorf("tc.wantAuxFuncEncoding =  %02x, want %02x", tc.wantAuxFuncEncoding, encodingArray[0])
				}
			}

			operation.NumerateInstruction(99)
			if operation.instructionNumber != 99 {
				t.Errorf("operation.instructionNumber = %d, want 99", operation.instructionNumber)
			}
		})
	}
}
