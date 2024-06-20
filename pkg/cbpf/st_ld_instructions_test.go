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
	"fmt"
	"reflect"
	"testing"
)

func TestStLdInstructionGenerationAndEncoding(t *testing.T) {
	testK := int32(65535)
	tests := []struct {
		testName     string
		instruction  *pb.Instruction
		wantJmpTrue  int32
		wantJmpFalse int32
		wantK        int32
		// The values for expected encoding are calculated manually
		wantEncoding string
	}{
		{
			testName:     "Encoding LD Instruction",
			instruction:  Ld(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x60, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDI Instruction",
			instruction:  Ldi(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x00, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDLen Instruction",
			instruction:  LdLen(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x80, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDAbsW Instruction",
			instruction:  LdAbsW(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x20, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDAbsH Instruction",
			instruction:  LdAbsH(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x28, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDAbsB Instruction",
			instruction:  LdAbsB(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x30, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDIndW Instruction",
			instruction:  LdIndW(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x40, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDIndH Instruction",
			instruction:  LdIndH(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x48, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDIndB Instruction",
			instruction:  LdIndB(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x50, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDx Instruction",
			instruction:  Ldx(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x61, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDxI Instruction",
			instruction:  Ldxi(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x01, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDxLen Instruction",
			instruction:  LdxLen(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x81, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDxAbs Instruction",
			instruction:  LdxAbs(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x21, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding LDxb Instruction",
			instruction:  Ldxb(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0xb1, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding ST Instruction",
			instruction:  St(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x62, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding STx Instruction",
			instruction:  Stx(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x63, 1, 2, 0x0000ffff}",
		},
	}
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction := tc.instruction
			t.Logf("Running test case %s", tc.testName)
			if instruction.Jt != tc.wantJmpTrue {
				t.Fatalf("instruction.jt = %d, want %d", instruction.Jt, tc.wantJmpTrue)
			}

			if instruction.Jf != tc.wantJmpFalse {
				t.Fatalf("instruction.jf = %d, want %d", instruction.Jf, tc.wantJmpFalse)
			}

			if instruction.K != tc.wantK {
				t.Fatalf("instruction.k = %d, want %d", instruction.K, tc.wantK)
			}

			op := fmt.Sprintf("%02x", int16(instruction.Opcode))
			jt := fmt.Sprintf("%x", int8(instruction.Jt))
			jf := fmt.Sprintf("%x", int8(instruction.Jf))
			k := fmt.Sprintf("%08x", int32(instruction.K))
			encoding := "{0x" + op + ", " + jt + ", " + jf + ", 0x" + k + "}"
			if !reflect.DeepEqual(encoding, tc.wantEncoding) {
				t.Fatalf("instruction = %s, want %s", encoding, tc.wantEncoding)
			}
		})
	}
}
