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
func InstructionSequence(instructions ...Instruction) ([]Instruction, error) {
	for index, inst := range instructions {
		if inst == nil {
			return nil, fmt.Errorf("Nil instruction at index %d, did you pass an unsigned int value?", index)
		}
	}
	return instructions, nil
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
