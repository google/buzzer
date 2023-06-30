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

func checkOperationImpl(t *testing.T, ptr Operation, expectedOperations []Operation) error {
	t.Logf("checking ptr: %v, expectedOperations: %v", ptr, expectedOperations)
	for i := 0; i < len(expectedOperations); {
		operation := expectedOperations[i]
		if ptr != operation {
			return fmt.Errorf("mismatched operation at index %d, want %v, have %v", i, operation, ptr)
		}

		checkJmpFunction := func(index, falseBranchSize int, jmpInstr Operation, t *testing.T, nextInstr Operation) (int, error) {
			if falseBranchSize == 0 {
				// If falseBranch is 0, then it must be an exit operation.
				return index + 1, nil
			}
			var falseBranchExpectedOperations []Operation

			// Start represents the index of the first instruction of the
			// false branch. End represents the index of the first instruction
			// of the true branch.
			start := index + 1
			end := start + falseBranchSize

			// Check that we are in bounds
			if end > len(expectedOperations) {
				return 0, fmt.Errorf("Jump Instruction (%v) at index %d out of program bounds. end = %d, len(expectedOperations) = %d", jmpInstr, i, end, len(expectedOperations))
			} else {
				falseBranchExpectedOperations = expectedOperations[start:end]
			}
			if falseBranchCheck := checkOperationImpl(t, nextInstr, falseBranchExpectedOperations); falseBranchCheck != nil {
				return 0, falseBranchCheck
			}
			return end, nil
		}

		if jmpInstr, ok := ptr.(*IMMJMPOperation); ok {
			if jmpInstr.FalseBranchSize == 0 && jmpInstr.Instruction != JmpExit {
				t.Fatalf("Jump instruction with false branch size of 0 and not an exit operation or uncodintional jump at index %d (%v)", i, jmpInstr)
			}
			nextInstrIndex, err := checkJmpFunction(i, int(jmpInstr.FalseBranchSize), jmpInstr, t, jmpInstr.FalseBranchNextInstr)
			if err != nil {
				return err
			}
			i = nextInstrIndex
		} else if jmpInstr, ok := ptr.(*RegJMPOperation); ok {
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
		testName   string
		operations []Operation
	}{
		{
			testName:   "Instruction chain no jumps",
			operations: []Operation{Mov64(RegR0, 0), Mul64(RegR0, 10), Mov64(RegR0, RegR1), Exit()},
		},
		{
			testName:   "Instruction chain with jumps",
			operations: []Operation{Mov64(RegR0, 0), JmpGT(RegR0, 0, 4), Mul64(RegR0, 10), JmpLT(RegR0, RegR1, 2), Jmp(1), Mov64(RegR0, RegR1), Exit()},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			root, err := InstructionSequence(tc.operations...)
			if err != nil {
				t.Fatalf("InstructionSequence returned error: %v", err)
			}
			result := checkOperationImpl(t, root, tc.operations)
			if result != nil {
				t.Fatalf("%v", result)
			}
		})
	}
}
