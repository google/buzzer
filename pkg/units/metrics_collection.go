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
	"sync"
)

// MetricsCollection Holds the actual metrics that have been collected so far
// and provides a way to access them in a thread safe manner.
type MetricsCollection struct {
	metricsLock sync.Mutex

	// Metrics start here
	programsVerified int
	validPrograms    int
	coverageManager  *CoverageManager
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

func (mc *MetricsCollection) getMetrics() (int, int, []CoverageInfo) {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	covArray := []CoverageInfo{}
	for _, cov := range *mc.coverageManager.GetCoverageInfoMap() {
		covCopy := *cov
		covCopy.coveredLines = nil
		covCopy.coveredLines = append(covCopy.coveredLines, cov.coveredLines...)
		covArray = append(covArray, covCopy)
	}
	return mc.programsVerified, mc.validPrograms, covArray
}
