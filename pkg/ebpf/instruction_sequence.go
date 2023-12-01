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
)

// InstructionSequence abstracts away the process of creating a sequence of
// ebpf instructions. This should make writing ebpf programs in buzzer
// more readable and easier to achieve.
func InstructionSequence(instructions ...Instruction) (Instruction, error) {
	return instructionSequenceImpl(instructions)
}

// In order to deal with things like nested jumps, the instruction sequence
// feature needs to be a recursive function, hide the actual implementation
// from users using a non exported function.
func instructionSequenceImpl(instructions []Instruction) (Instruction, error) {
	if len(instructions) == 0 {
		// no more instructions to process, break the recursion.
		return nil, nil
	}
	var root, ptr Instruction
	advancePointer := func(i Instruction) {
		if root == nil {
			root = i
			ptr = root
		} else {
			ptr.SetNextInstruction(i)
			ptr = i
		}
	}

	for i := 0; i < len(instructions); i++ {
		instruction := instructions[i]

		if jmpInstr, ok := instruction.(JmpInstruction); ok {
			if jmpInstr.GetFalseBranchSize() == 0 && jmpInstr.GetOpcode() != JmpExit {
				return nil, fmt.Errorf("Only Exit() can have an offset of 0")
			}
			falseBranchNextInstr, trueBranchNextInstr, err := handleJmpInstruction(instructions[i:], jmpInstr.GetFalseBranchSize())
			if err != nil {
				return nil, err
			}

			jmpInstr.SetFalseBranchNextInstr(falseBranchNextInstr)
			jmpInstr.SetTrueBranchNextInstr(trueBranchNextInstr)

			advancePointer(jmpInstr)

			// Break here because handleJmpInstruction should have processed the rest of the ebpf program.
			break
		} else {
			advancePointer(instruction)
		}
	}
	return root, nil
}

func handleJmpInstruction(instructions []Instruction, offset int16) (Instruction, Instruction, error) {
	if len(instructions) == 0 {
		// TODO: here and below, to improve testing lets define the possible
		// errors in a list somewhere else so we can compare directly that we
		// got the error we expect.
		return nil, nil, fmt.Errorf("handleJmpInstruction invocation should receive at least 1 instruction")
	}
	trueBranchStartIndex := int(offset) + 1
	if trueBranchStartIndex > len(instructions) {
		// TODO: For this error message and others, it would make debugging
		// easier if we could put the offending instruction.
		// For that we would need a way to convert an instruction to a
		// readable string, this is easy to do but let's do it in a follow
		// up patch.
		return nil, nil, fmt.Errorf("Jmp goes out of bounds")
	}

	// instructions[0] should be the jump itself.
	falseBranchInstrs := instructions[1:trueBranchStartIndex]
	trueBranchInstrs := instructions[trueBranchStartIndex:]

	falseBranchNextInstr, err := instructionSequenceImpl(falseBranchInstrs)
	if err != nil {
		return nil, nil, err
	}
	trueBranchNextInstr, err := instructionSequenceImpl(trueBranchInstrs)
	if err != nil {
		return nil, nil, err
	}
	return falseBranchNextInstr, trueBranchNextInstr, nil
}

// This function is meant to be used by all the Instruction Helper functions,
// to test if the supplied src parameter is of type int. Callers of the helper
// functions might provide an int, int64, int32, int16, int8, int as src
// parameter and it makes sense to centralize the logic to check for a data
// type here.
//
// If the passed data is indeed of an int data type, bool is true and
// the value casted to int() is returned.
//
// If it is not, it returns false and an arbitrary int()
func isIntType(src interface{}) (bool, int) {
	if srcInt, ok := src.(int); ok {
		return true, srcInt
	} else if srcInt64, ok := src.(int64); ok {
		return true, int(srcInt64)
	} else if srcInt32, ok := src.(int32); ok {
		return true, int(srcInt32)
	} else if srcInt16, ok := src.(int16); ok {
		return true, int(srcInt16)
	} else if srcInt8, ok := src.(int8); ok {
		return true, int(srcInt8)
	}

	return false, int(0)
}
