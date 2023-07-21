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

func TestMemoryInstructionCorrectEncoding(t *testing.T) {
	tests := []struct {
		testName string
		imm      int32
		size     uint8
		mode     uint8
		srcReg   *Register
		dstReg   *Register
		insClass uint8
		offset   int16

		// The values for expected encoding are calculated manually by
		// following: http://shortn/_YhGoFtsPl9
		wantEnc []uint64

		// Check that the auxiliar functions that return the bytecode
		// directly have the values we expect.
		wantAuxFuncEncoding uint64
	}{
		{
			testName:            "Encoding Store Instruction",
			size:                StLdSizeW,
			imm:                 int32(-65535),
			mode:                StLdModeMEM,
			srcReg:              RegR0,
			dstReg:              RegR1,
			insClass:            InsClassStx,
			offset:              4,
			wantEnc:             []uint64{0xffff000100040163},
			wantAuxFuncEncoding: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			operation := MemoryInstruction{
				BaseInstruction: BaseInstruction{
					InstructionClass: tc.insClass,
				},
				Size:   tc.size,
				Mode:   tc.mode,
				DstReg: tc.dstReg,
				SrcReg: tc.srcReg,
				Offset: tc.offset,
				Imm:    tc.imm,
			}

			encodingArray := operation.GenerateBytecode()

			if !reflect.DeepEqual(encodingArray, tc.wantEnc) {
				t.Fatalf("operation.generateBytecode() = %x, want %x", encodingArray, tc.wantEnc)
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
