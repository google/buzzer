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
	"errors"
	"testing"
)

func TestControlUnitInitSuccess(t *testing.T) {
	tests := []struct {
		testName   string
		runMode    string
		fuzzStrat  string
		verbosity  int
		localIP    string
		localPort  uint
		remoteIP   string
		remotePort uint

		eVerbosity VerbosityLevel
		eRunMode   RunMode
	}{
		{
			testName:   "Server mode info verbosity",
			runMode:    "server",
			fuzzStrat:  "parse_verifier_log",
			verbosity:  1,
			localIP:    "127.0.0.1",
			localPort:  4444,
			remoteIP:   "127.0.0.1",
			remotePort: 4444,

			eVerbosity: Info,
			eRunMode:   Server,
		}, {
			testName:   "Client mode quiet verbosity",
			runMode:    "client",
			fuzzStrat:  "parse_verifier_log",
			verbosity:  0,
			localIP:    "127.0.0.1",
			localPort:  4444,
			remoteIP:   "127.0.0.1",
			remotePort: 4444,

			eVerbosity: Quiet,
			eRunMode:   Client,
		}, {
			testName:   "Standalone mode Verbose verbosity",
			runMode:    "standalone",
			fuzzStrat:  "parse_verifier_log",
			verbosity:  2,
			localIP:    "127.0.0.1",
			localPort:  4444,
			remoteIP:   "127.0.0.1",
			remotePort: 4444,

			eVerbosity: Verbose,
			eRunMode:   Standalone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			t.Logf("Running test case %s", tc.testName)
			cu := &ControlUnit{}
			if err := cu.Init(&Executor{}, tc.runMode, tc.fuzzStrat, tc.verbosity, tc.localIP, tc.localPort, tc.remoteIP, tc.remotePort); err != nil {
				t.Fatalf("Unexpected error %s", err)
			}

			if cu.GetVerbosityLevel() != tc.eVerbosity {
				t.Fatalf("cu.GetVerbosityLevel() = %d, want verbosity %d ", cu.vl, tc.eVerbosity)
			}

			if cu.GetRunMode() != tc.eRunMode {
				t.Fatalf("cu.GetRunMode() = %s, want run mode %s ", cu.rm, tc.eRunMode)
			}

			if !cu.IsReady() {
				t.Fatalf("Control unit was not marked as ready at the end of init")
			}
		})
	}
}

func TestControlUnitInitFailure(t *testing.T) {
	tests := []struct {
		testName   string
		runMode    string
		fuzzStrat  string
		verbosity  int
		localIP    string
		localPort  uint
		remoteIP   string
		remotePort uint

		eError error
	}{
		{
			testName:   "Error due to unknown run Mode",
			runMode:    "unknown",
			fuzzStrat:  "parse_verifier_log",
			verbosity:  1,
			localIP:    "127.0.0.1",
			localPort:  4444,
			remoteIP:   "127.0.0.1",
			remotePort: 4444,

			eError: errors.New("unknown run mode: unknown"),
		}, {
			testName:   "Error due to unknown verbosity level",
			runMode:    "server",
			fuzzStrat:  "parse_verifier_log",
			verbosity:  -1,
			localIP:    "127.0.0.1",
			localPort:  4444,
			remoteIP:   "127.0.0.1",
			remotePort: 4444,

			eError: errors.New("unknown verbosity level: -1"),
		},
	}

	for _, tc := range tests {
		t.Logf("Running test case %s", tc.testName)
		cu := &ControlUnit{}
		err := cu.Init(&Executor{}, tc.runMode, tc.fuzzStrat, tc.verbosity, tc.localIP, tc.localPort, tc.remoteIP, tc.remotePort)
		if err == nil {
			t.Fatalf("Control Unit Init Succeeded unexpectedly")
		}

		if err.Error() != tc.eError.Error() {
			t.Fatalf("Got error %s, but expected %s", err, tc.eError)
		}
	}
}
