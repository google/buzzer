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
	pb "buzzer/proto/ebpf_go_proto"
	"fmt"
)

// InstructionSequence abstracts away the process of creating a sequence of
// ebpf instructions. This should make writing ebpf programs in buzzer
// more readable and easier to achieve.
func InstructionSequence(instructions ...*pb.Instruction) ([]*pb.Instruction, error) {
	for index, inst := range instructions {
		if inst == nil {
			return nil, fmt.Errorf("Nil instruction at index %d, did you pass an unsigned int value?", index)
		}
	}
	return instructions, nil
}
