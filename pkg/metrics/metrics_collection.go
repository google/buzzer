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

package metrics

import (
	"sync"
)

type coverageInfo struct {
	fileName     string
	fullPath     string
	coveredLines []int
}

// Collection Holds the actual metrics that have been collected so far
// and provides a way to access them in a thread safe manner.
type Collection struct {
	metricsLock sync.Mutex

	// Metrics start here
	programsVerified int
	validPrograms    int
	coverageInfoMap  map[string]*coverageInfo
}

func (mc *Collection) recordVerifiedProgram() {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	mc.programsVerified++
}

func (mc *Collection) recordValidProgram() {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	mc.validPrograms++
}

func (mc *Collection) recordCoverageLine(fileName, fullPath string, lineNumber int) {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	if info, ok := mc.coverageInfoMap[fileName]; !ok {
		mc.coverageInfoMap[fileName] = &coverageInfo{
			fileName:     fileName,
			fullPath:     fullPath,
			coveredLines: []int{lineNumber},
		}
	} else {
		info.coveredLines = append(info.coveredLines, lineNumber)
	}
}

func (mc *Collection) getProgramsVerified() int {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	return mc.programsVerified
}

func (mc *Collection) getMetrics() (int, int, []coverageInfo) {
	mc.metricsLock.Lock()
	defer mc.metricsLock.Unlock()
	covArray := []coverageInfo{}
	for _, cov := range mc.coverageInfoMap {
		covCopy := *cov
		covCopy.coveredLines = nil
		covCopy.coveredLines = append(covCopy.coveredLines, cov.coveredLines...)
		covArray = append(covArray, covCopy)
	}
	return mc.programsVerified, mc.validPrograms, covArray
}
