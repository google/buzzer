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
	"os"
	"path/filepath"
	"testing"
)

var testDataPath = "testdata/"

func TestFromVerifierTrace(t *testing.T) {
	tests := []struct {
		testName  string
		path      string
		offset    int32
		registers []uint8
		values    []uint64
		wantError bool
	}{
		{
			testName:  "Good Trace 1",
			path:      filepath.Join(testDataPath, "good-trace-0001.log"),
			offset:    15,
			registers: []uint8{9},
			values:    []uint64{127},
		},
		{
			testName:  "Bad Trace Offset",
			path:      filepath.Join(testDataPath, "bad-trace-0001.log"),
			wantError: true,
		},
		{
			testName:  "Bad Trace Reg Value",
			path:      filepath.Join(testDataPath, "bad-trace-0002.log"),
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)

			traceContents, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal("Error reading source file:", err)
			}

			oracle, err := FromVerifierTrace(string(traceContents))
			if !tc.wantError && (oracle == nil || err != nil) {
				t.Fatal("Did not want error while creating oracle")
			}
			if tc.wantError && (err == nil) {
				t.Errorf("Want error, got nothing")
			}

			for i := range tc.registers {
				value, ok, err := oracle.LookupRegValue(tc.offset, tc.registers[i])
				if err != nil {
					t.Errorf("An unexpected error %v was received", err)
				}
				if i < len(tc.values) && !ok {
					t.Errorf("Wanted a value for register %q at offset %q", tc.registers[i], tc.offset)
				}
				if i >= len(tc.values) && ok {
					t.Errorf("Did not want a value for register %q at offset %q", tc.registers[i], tc.offset)
				}
				if i < len(tc.values) && value != tc.values[i] {
					t.Errorf("Got %q, but want %q", value, tc.values[i])
				}
			}
		})
	}
}
