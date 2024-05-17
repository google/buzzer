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

	pb "buzzer/proto/ebpf_go_proto"
)

func TestInstructionChainHelperTest(t *testing.T) {
	tests := []struct {
		testName      string
		operations    []*pb.Instruction
		expectedError error
	}{
		{
			testName: "Instruction chain no jumps",
			operations: []*pb.Instruction{
				Mov64(pb.Reg_R0, 0),
				Mul64(pb.Reg_R0, 10),
				Mov64(pb.Reg_R0, pb.Reg_R1),
				Exit()},
			expectedError: nil,
		},
		{
			testName: "Instruction chain with jumps",
			operations: []*pb.Instruction{
				Mov64(pb.Reg_R0, 0),
				JmpGT(pb.Reg_R0, 0, 4),
				Mul64(pb.Reg_R0, 10),
				JmpLT(pb.Reg_R0, pb.Reg_R1, 2),
				Jmp(1),
				Mov64(pb.Reg_R0,
					pb.Reg_R1), Exit()},
			expectedError: nil,
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

			if !reflect.DeepEqual(root, tc.operations) {
				t.Errorf("Want instruction array = %v, have %v", tc.operations, root)
			}
		})
	}
}
