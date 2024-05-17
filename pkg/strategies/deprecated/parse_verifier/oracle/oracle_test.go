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

package oracle

import (
	"testing"

	"buzzer/pkg/ebpf/ebpf"
)

func TestLookupRegValue(t *testing.T) {
	tests := []struct {
		testName      string
		offset        int32
		registers     []uint8
		values        []uint64
		expectedError bool
	}{
		{
			testName:  "Empty",
			offset:    0,
			registers: []uint8{0},
		},
		{
			testName:      "Bad Register",
			offset:        0,
			registers:     []uint8{13},
			values:        []uint64{0xAB},
			expectedError: true,
		},
		{
			testName:  "Initialize Values",
			offset:    0,
			registers: []uint8{0, 4},
			values:    []uint64{0xAB, 0xCD},
		},
		{
			testName:  "Uninitialized Value",
			offset:    0,
			registers: []uint8{0, 4, 8},
			values:    []uint64{0xAB},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)

			oracle := NewRegisterOracle()
			if tc.registers != nil {
				for i := range tc.registers {
					if i < len(tc.values) && tc.registers[i] <= ebpf.RegisterCount {
						oracle.SetRegValue(tc.offset, tc.registers[i], tc.values[i])
					}
				}
			}

			if !tc.expectedError {
				for i := range tc.registers {
					value, ok, err := oracle.LookupRegValue(tc.offset, tc.registers[i])
					if err != nil {
						t.Errorf("An unexpected error %v was received", err)
					}
					if i < len(tc.values) && !ok {
						t.Errorf("Expected a value for register %q at offset %q", tc.registers[i], tc.offset)
					}
					if i >= len(tc.values) && ok {
						t.Errorf("Did not expect value for register %q at offset %q", tc.registers[i], tc.offset)
					}
					if i < len(tc.values) && value != tc.values[i] {
						t.Errorf("Output %q not equal to expected %q", value, tc.values[i])
					}
				}
			} else {
				for i := range tc.registers {
					_, ok, err := oracle.LookupRegValue(tc.offset, tc.registers[i])
					if err == nil {
						t.Errorf("Expected error, but did not receive one")
					}
					if ok {
						t.Errorf("Unexpectedly received a known value with an error")
					}
				}
			}
		})
	}
}

func TestSetRegValue(t *testing.T) {
	tests := []struct {
		testName      string
		offset        int32
		registers     []uint8
		values        []uint64
		expectedError bool
	}{
		{
			testName:      "Bad Register",
			offset:        0,
			registers:     []uint8{13},
			values:        []uint64{0xAB},
			expectedError: true,
		},
		{
			testName:  "Initialize Values",
			offset:    0,
			registers: []uint8{0, 4},
			values:    []uint64{0xAB, 0xCD},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)

			oracle := NewRegisterOracle()

			if !tc.expectedError {
				for i := range tc.registers {
					err := oracle.SetRegValue(tc.offset, tc.registers[i], tc.values[i])
					if err != nil {
						t.Errorf("An unexpected error %v was received", err)
					}
				}
			} else {
				for i := range tc.registers {
					err := oracle.SetRegValue(tc.offset, tc.registers[i], tc.values[i])
					if err == nil {
						t.Errorf("Expected error, but did not receive one")
					}
				}
			}
		})
	}
}
