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

package units

import (
	"testing"
)

func TestControlUnitInitSuccess(t *testing.T) {
	tests := []struct {
		testName   string
		runMode    string
		fuzzStrat  string
	}{
		{
			testName:   "Server mode info verbosity",
			runMode:    "server",
			fuzzStrat:  "parse_verifier_log",
		}, {
			testName:   "Client mode quiet verbosity",
			runMode:    "client",
			fuzzStrat:  "parse_verifier_log",
		}, {
			testName:   "Standalone mode Verbose verbosity",
			runMode:    "standalone",
			fuzzStrat:  "parse_verifier_log",
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			cu := &ControlUnit{}
			if err := cu.Init(&Executor{}, tc.runMode, tc.fuzzStrat); err != nil {
				t.Fatalf("Unexpected error %s", err)
			}

			if !cu.IsReady() {
				t.Fatalf("Control unit was not marked as ready at the end of init")
			}
		})
	}
}
