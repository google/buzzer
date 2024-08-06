// Copyright 2024 Google LLC
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

func TestStLdInstructionGenerationAndEncoding(t *testing.T) {
	testK := int32(65535)
	tests := []struct {
		testName     string
		instruction  *pb.Instruction
		wantClass    int32
		wantSize     int32
		wantMode     int32
		wantJmpTrue  int32
		wantJmpFalse int32
		wantK        int32
	}{
		{
			testName:     "Encoding LD Instruction",
			instruction:  Ld(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeMEM),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDI Instruction",
			instruction:  Ldi(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeIMM),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDLen Instruction",
			instruction:  LdLen(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeLEN),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDAbsW Instruction",
			instruction:  LdAbsW(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeABS),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDAbsH Instruction",
			instruction:  LdAbsH(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeH),
			wantMode:     int32(pb.StLdMode_StLdModeABS),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDAbsB Instruction",
			instruction:  LdAbsB(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeB),
			wantMode:     int32(pb.StLdMode_StLdModeABS),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDIndW Instruction",
			instruction:  LdIndW(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeIND),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDIndH Instruction",
			instruction:  LdIndH(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeH),
			wantMode:     int32(pb.StLdMode_StLdModeIND),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDIndB Instruction",
			instruction:  LdIndB(testK),
			wantClass:    int32(pb.InsClass_InsClassLd),
			wantSize:     int32(pb.StLdSize_StLdSizeB),
			wantMode:     int32(pb.StLdMode_StLdModeIND),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDx Instruction",
			instruction:  Ldx(testK),
			wantClass:    int32(pb.InsClass_InsClassLdx),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeMEM),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDxI Instruction",
			instruction:  Ldxi(testK),
			wantClass:    int32(pb.InsClass_InsClassLdx),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeIMM),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDxLen Instruction",
			instruction:  LdxLen(testK),
			wantClass:    int32(pb.InsClass_InsClassLdx),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeLEN),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDxAbs Instruction",
			instruction:  LdxAbs(testK),
			wantClass:    int32(pb.InsClass_InsClassLdx),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeABS),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding LDxb Instruction",
			instruction:  Ldxb(testK),
			wantClass:    int32(pb.InsClass_InsClassLdx),
			wantSize:     int32(pb.StLdSize_StLdSizeB),
			wantMode:     int32(pb.StLdMode_StLdModeMSH),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding ST Instruction",
			instruction:  St(testK),
			wantClass:    int32(pb.InsClass_InsClassSt),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeMEM),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
		{
			testName:     "Encoding STx Instruction",
			instruction:  Stx(testK),
			wantClass:    int32(pb.InsClass_InsClassStx),
			wantSize:     int32(pb.StLdSize_StLdSizeW),
			wantMode:     int32(pb.StLdMode_StLdModeMEM),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
		},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction := tc.instruction
			t.Logf("Running test case %s", tc.testName)

			// The 3 LSB are the instruction class
			ocClass := instruction.Opcode & 0x07

			// The next 2 bit is the size
			ocSize := instruction.Opcode & 0x18

			// The 3 MSB are the operation mode
			ocMode := instruction.Opcode & 0xe0

			if ocClass != tc.wantClass {
				t.Fatalf("instruction.Opcode Class = %d, want %d", ocClass, tc.wantClass)
			}

			if ocSize != tc.wantSize {
				t.Fatalf("instruction.Opcode Size = %d, want %d", ocSize, tc.wantSize)
			}

			if ocMode != tc.wantMode {
				t.Fatalf("instruction.Opcode Mode = %d, want %d", ocMode, tc.wantMode)
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
