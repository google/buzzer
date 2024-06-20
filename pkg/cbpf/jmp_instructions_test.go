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

func TestJmpInstructionGenerationAndEncoding(t *testing.T) {
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
			testName:     "Encoding JmpJA Instruction",
			instruction:  JmpJA(1),
			wantJmpTrue:  1,
			wantJmpFalse: 0,
			wantK:        0,
			wantEncoding: "{0x05, 1, 0, 0x00000000}",
		},
		{
			testName:     "Encoding JmpEQ Instruction",
			instruction:  JmpEQ(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x15, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding JmpGT Instruction",
			instruction:  JmpGT(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x25, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding JmpGE Instruction",
			instruction:  JmpGE(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x35, 1, 2, 0x0000ffff}",
		},
		{
			testName:     "Encoding JmpSET Instruction",
			instruction:  JmpSET(1, 2, testK),
			wantJmpTrue:  1,
			wantJmpFalse: 2,
			wantK:        testK,
			wantEncoding: "{0x45, 1, 2, 0x0000ffff}",
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
