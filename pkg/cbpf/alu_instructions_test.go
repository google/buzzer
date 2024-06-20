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

func TestAluInstructionGenerationAndEncoding(t *testing.T) {
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
			testName:     "Add with Register as Source",
			instruction:  Add(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x0c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Add with Int as Source",
			instruction:  Add(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x04, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Sub Register as Source",
			instruction:  Sub(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x1c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Sub with Int as Source",
			instruction:  Sub(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x14, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Mul with Register as Source",
			instruction:  Mul(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x2c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Mul with Int as Source",
			instruction:  Mul(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x24, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Div with Register as Source",
			instruction:  Div(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x3c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Div with Int as Source",
			instruction:  Div(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x34, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "OR with Register as Source",
			instruction:  Or(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x4c, 0, 0, 0x00000001}",
		},
		{
			testName:     "OR with Int as Source",
			instruction:  Or(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x44, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "And with Register as Source",
			instruction:  And(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x5c, 0, 0, 0x00000001}",
		},
		{
			testName:     "And with Int as Source",
			instruction:  And(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x54, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Lsh with Register as Source",
			instruction:  Lsh(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x6c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Lsh with Int as Source",
			instruction:  Lsh(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x64, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Rsh with Register as Source",
			instruction:  Rsh(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x7c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Rsh with Int as Source",
			instruction:  Rsh(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x74, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Neg with Register as Source",
			instruction:  Neg(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x8c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Neg with Int as Source",
			instruction:  Neg(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x84, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Mod with Register as Source",
			instruction:  Mod(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0x9c, 0, 0, 0x00000001}",
		},
		{
			testName:     "Mod with Int as Source",
			instruction:  Mod(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0x94, 0, 0, 0x0000ffff}",
		},
		{
			testName:     "Xor with Register as Source",
			instruction:  Xor(X),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        int32(X),
			wantEncoding: "{0xac, 0, 0, 0x00000001}",
		},
		{
			testName:     "Xor with Int as Source",
			instruction:  Xor(testK),
			wantJmpTrue:  0,
			wantJmpFalse: 0,
			wantK:        testK,
			wantEncoding: "{0xa4, 0, 0, 0x0000ffff}",
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
