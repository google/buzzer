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
	"strings"
	"sync"
	"time"

	fpb "buzzer/proto/ffi_go_proto"
)

// MetricsCollection Holds the actual metrics that have been collected so far
// and provides a way to access them in a thread safe manner.
type MetricsCollection struct {
	metricsLock sync.Mutex

	// Metrics start here
	programsVerified  int
	validPrograms     int
	coverageManager   *CoverageManager
	latestVerifierLog string
	verifierVerdicts  map[string]int
}

func (mc *MetricsCollection) recordVerifiedProgram() {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	mc.programsVerified++
}

func (mc *MetricsCollection) recordValidProgram() {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	mc.validPrograms++
}

func (mc *MetricsCollection) getProgramsVerified() int {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	return mc.programsVerified
}

func (mc *MetricsCollection) getCoverageHistory() map[time.Time]int {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	return mc.coverageManager.GetCoverageHistory()
}

func (mc *MetricsCollection) getMetrics() (int, int, []CoverageInfo) {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	covArray := []CoverageInfo{}
	for filePath, cov := range *mc.coverageManager.GetCoverageInfoMap() {
		covInfo := CoverageInfo{
			coveredLines: []int{},
		}

		pathSplit := strings.Split(filePath, "/")
		if len(pathSplit) == 0 {
			continue
		}

		covInfo.fileName = pathSplit[len(pathSplit)-1]
		covInfo.fullPath = filePath
		covInfo.coveredLines = append(covInfo.coveredLines, cov...)

		covArray = append(covArray, covInfo)
	}
	return mc.programsVerified, mc.validPrograms, covArray
}

// processVerifierLog serves to get metrics out of what the verifier has
// judged from the programs.
func (mc *MetricsCollection) processVerifierLog(vres *fpb.ValidationResult) {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	log := vres.GetVerifierLog()
	if len(log) == 0 {
		return
	}
	mc.latestVerifierLog = log

	if vres.IsValid {
		// If it the program is valid, no need to record any verifier
		// error message.
		return
	}

	logSplits := strings.Split(log, "\n")

	// The verifier error is in the second to last line of the log.
	// There is an extra new line at the end, this is why the -3
	verifierError := logSplits[len(logSplits)-3]

	if _, ok := mc.verifierVerdicts[verifierError]; !ok {
		mc.verifierVerdicts[verifierError] = 1
	} else {
		mc.verifierVerdicts[verifierError] += 1
	}
}

func (mc *MetricsCollection) getLatestLog() string {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	return mc.latestVerifierLog
}

func (mc *MetricsCollection) getVerifierVerdicts() map[string]int {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	return mc.verifierVerdicts
}
