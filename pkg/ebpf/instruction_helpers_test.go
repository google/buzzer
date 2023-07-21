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
	"fmt"
	"testing"
)

func checkInstructionImpl(t *testing.T, ptr Instruction, expectedInstructions []Instruction) error {
	t.Logf("checking ptr: %v, expectedInstructions: %v", ptr, expectedInstructions)
	for i := 0; i < len(expectedInstructions); {
		operation := expectedInstructions[i]
		if ptr != operation {
			return fmt.Errorf("mismatched operation at index %d, want %v, have %v", i, operation, ptr)
		}

		checkJmpFunction := func(index, falseBranchSize int, jmpInstr Instruction, t *testing.T, nextInstr Instruction) (int, error) {
			if falseBranchSize == 0 {
				// If falseBranch is 0, then it must be an exit operation.
				return index + 1, nil
			}
			var falseBranchExpectedInstructions []Instruction

			// Start represents the index of the first instruction of the
			// false branch. End represents the index of the first instruction
			// of the true branch.
			start := index + 1
			end := start + falseBranchSize

			// Check that we are in bounds
			if end > len(expectedInstructions) {
				return 0, fmt.Errorf("Jump Instruction (%v) at index %d out of program bounds. end = %d, len(expectedInstructions) = %d", jmpInstr, i, end, len(expectedInstructions))
			} else {
				falseBranchExpectedInstructions = expectedInstructions[start:end]
			}
			if falseBranchCheck := checkInstructionImpl(t, nextInstr, falseBranchExpectedInstructions); falseBranchCheck != nil {
				return 0, falseBranchCheck
			}
			return end, nil
		}

		if jmpInstr, ok := ptr.(*IMMJMPInstruction); ok {
			if jmpInstr.FalseBranchSize == 0 && jmpInstr.Opcode != JmpExit {
				t.Fatalf("Jump instruction with false branch size of 0 and not an exit operation or uncodintional jump at index %d (%v)", i, jmpInstr)
			}
			nextInstrIndex, err := checkJmpFunction(i, int(jmpInstr.FalseBranchSize), jmpInstr, t, jmpInstr.FalseBranchNextInstr)
			if err != nil {
				return err
			}
			i = nextInstrIndex
		} else if jmpInstr, ok := ptr.(*RegJMPInstruction); ok {
			if jmpInstr.FalseBranchSize == 0 {
				t.Fatalf("A jump reg instruction cannot have false branch of 0 at index %d (%v)", i, jmpInstr)
			}
			nextInstrIndex, err := checkJmpFunction(i, int(jmpInstr.FalseBranchSize), jmpInstr, t, jmpInstr.FalseBranchNextInstr)
			if err != nil {
				return err
			}
			i = nextInstrIndex
		} else {
			i += 1
		}

		ptr = ptr.GetNextInstruction()
	}
	return nil
}

func TestInstructionChainHelperTest(t *testing.T) {
	tests := []struct {
		testName      string
		operations    []Instruction
		expectedError error
	}{
		{
			testName:      "Instruction chain no jumps",
			operations:    []Instruction{Mov64(RegR0, 0), Mul64(RegR0, 10), Mov64(RegR0, RegR1), Exit()},
			expectedError: nil,
		},
		{
			testName:      "Instruction chain with jumps",
			operations:    []Instruction{Mov64(RegR0, 0), JmpGT(RegR0, 0, 4), Mul64(RegR0, 10), JmpLT(RegR0, RegR1, 2), Jmp(1), Mov64(RegR0, RegR1), Exit()},
			expectedError: nil,
		},
		{
			testName:      "Jump imm With offset of 0",
			operations:    []Instruction{Mov64(RegR0, 0), JmpGT(RegR0, 0, 0), Exit()},
			expectedError: fmt.Errorf("Only Exit() and Jmp() can have an offset of 0"),
		},
		{
			testName:      "Jump reg With offset of 0",
			operations:    []Instruction{Mov64(RegR0, 0), JmpLT(RegR0, RegR1, 0), Exit()},
			expectedError: fmt.Errorf("JmpReg instruction cannot have jump offset of 0"),
		},
		{
			testName:      "Jump goes out of bounds",
			operations:    []Instruction{Mov64(RegR0, 0), JmpGT(RegR0, 0, 2), Exit()},
			expectedError: fmt.Errorf("Jmp goes out of bounds"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			root, err := InstructionSequence(tc.operations...)
			if tc.expectedError != nil {
				if err.Error() != tc.expectedError.Error() {
					t.Fatalf("Want error %v, got %v", tc.expectedError, err)
				}
				return
			}
			result := checkInstructionImpl(t, root, tc.operations)
			if result != nil {
				t.Fatalf("%v", result)
			}
		})
	}
}
