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

package cbpf

import (
	pb "buzzer/proto/cbpf_go_proto"
	"testing"
)

func TestJmpInstructionGenerationAndEncoding(t *testing.T) {
	testK := int32(65535)
	tests := []struct {
		testName             string
		instruction          *pb.Instruction
		wantInstructionClass int32
		wantSrc              int32
		wantOperationCode    int32
		wantJmpTrue          int32
		wantJmpFalse         int32
		wantK                int32
	}{
		{
			testName:             "Encoding JmpJA Instruction",
			instruction:          JmpJA(1),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJA),
			wantJmpTrue:          1,
			wantJmpFalse:         0,
			wantK:                0,
		},
		{
			testName:             "Encoding JmpEQ Instruction",
			instruction:          JmpEQ(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJEQ),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
		{
			testName:             "Encoding JmpGT Instruction",
			instruction:          JmpGT(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJGT),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
		{
			testName:             "Encoding JmpGE Instruction",
			instruction:          JmpGE(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJGE),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
		{
			testName:             "Encoding JmpSET Instruction",
			instruction:          JmpSET(1, 2, testK),
			wantInstructionClass: int32(pb.InsClass_InsClassJmp),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.JmpOperationCode_JmpJSET),
			wantJmpTrue:          1,
			wantJmpFalse:         2,
			wantK:                testK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction := tc.instruction
			t.Logf("Running test case %s", tc.testName)

			if (instruction.Opcode & 0x07) != tc.wantInstructionClass {
				t.Fatalf("instrcution.Opcode Class = %d, want %d", instruction.Opcode&0x07, tc.wantInstructionClass)
			}

			if (instruction.Opcode & 0x08) != tc.wantSrc {
				t.Fatalf("instrcution.Opcode Source = %d, want %d", instruction.Opcode&0x08, tc.wantSrc)
			}

			if (instruction.Opcode & 0xf0) != tc.wantOperationCode {
				t.Fatalf("instrcution.Opcode Code = %d, want %d", instruction.Opcode&0xf0, tc.wantOperationCode)
			}

			if instruction.Jt != tc.wantJmpTrue {
				t.Fatalf("instruction.jt = %d, want %d", instruction.Jt, tc.wantJmpTrue)
			}

			if instruction.Jf != tc.wantJmpFalse {
				t.Fatalf("instruction.jf = %d, want %d", instruction.Jf, tc.wantJmpFalse)
			}

			if instruction.K != tc.wantK {
				t.Fatalf("instruction.k = %d, want %d", instruction.K, tc.wantK)
			}

		})
	}
}
