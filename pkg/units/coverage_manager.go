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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CoverageInfo struct {
	fileName     string
	fullPath     string
	coveredLines []int
}

// CoverageManager deals with everything coverage related.
type CoverageManager struct {
	coverageLock sync.Mutex

	coverageCache   map[uint64]string
	coverageInfoMap map[string][]int
	coverageHistory map[time.Time]int
	lastMaxCoverage int

	addressToLineFunction func(string) (string, error)
}

// GetCoverageHistory returns the record of how many lines of coverage have
// we got with buzzer.
func (cm *CoverageManager) GetCoverageHistory() map[time.Time]int {
	cm.coverageLock.Lock()
	defer cm.coverageLock.Unlock()
	return cm.coverageHistory
}

// ProcessCoverageAddresses converts raw coverage hex addresses into line
// numbers and files, it also caches the results.
func (cm *CoverageManager) ProcessCoverageAddresses(cov []uint64) (map[uint64]string, error) {
	cm.coverageLock.Lock()
	defer cm.coverageLock.Unlock()

	unknownAddr := []uint64{}
	for _, address := range cov {
		if _, ok := cm.coverageCache[address]; !ok {
			unknownAddr = append(unknownAddr, address)
		}
	}

	// Only record increases of coverage based on the sum of known and unknown addresses.
	if cm.lastMaxCoverage < len(unknownAddr)+len(cm.coverageCache) {
		cm.lastMaxCoverage = len(unknownAddr) + len(cm.coverageCache)
		cm.coverageHistory[time.Now()] = cm.lastMaxCoverage
	}

	convertAddresses := func() map[uint64]string {
		coveredLines := make(map[uint64]string)
		for _, addr := range cov {
			line, ok := cm.coverageCache[addr]
			if ok {
				coveredLines[addr] = line
			}
		}
		return coveredLines
	}

	if len(unknownAddr) == 0 {
		return convertAddresses(), nil
	}

	inputString := ""
	for _, ukAddr := range unknownAddr {
		inputString += fmt.Sprintf("%02x\n", ukAddr)
	}

	outString, err := cm.addressToLineFunction(inputString)
	if err != nil {
		fmt.Printf("addressToLine error: %v\n", err)
		return nil, err
	}

	coverage := strings.Split(outString, "\n")
	for i, line := range coverage {
		if len(line) == 0 {
			continue
		}
		lineSplit := strings.Split(line, " ")
		if len(lineSplit) == 0 {
			continue
		}
		cleanedLine := lineSplit[0]
		pathSplit := strings.Split(cleanedLine, "/")
		if len(pathSplit) == 0 {
			continue
		}
		fnAndLn := strings.Split(pathSplit[len(pathSplit)-1], ":")
		if len(fnAndLn) == 0 {
			continue
		}
		fileName := fnAndLn[0]
		lineNumber, err := strconv.Atoi(fnAndLn[1])
		if err != nil {
			return nil, err
		}
		fullPath := strings.Split(cleanedLine, ":")[0]

		cm.coverageCache[unknownAddr[i]] = fnAndLn[0] + ":" + fnAndLn[1]
		cm.recordCoverageLine(fileName, fullPath, lineNumber)
	}

	return convertAddresses(), nil
}

// RecordCoverageLine records a new observed coverage line and adds it to the
// corresponding file cache.
func (cm *CoverageManager) recordCoverageLine(fileName, fullPath string, lineNumber int) {
	if linesForFile, ok := cm.coverageInfoMap[fullPath]; !ok {
		cm.coverageInfoMap[fullPath] = []int{lineNumber}
	} else {
		cm.coverageInfoMap[fullPath] = append(linesForFile, lineNumber)
	}
}

// GetCoverageInfoMap returns the coverage info cache.
func (cm *CoverageManager) GetCoverageInfoMap() *map[string][]int {
	return &cm.coverageInfoMap
}

func NewCoverageManager(processingFunction func(string) (string, error)) *CoverageManager {
	return &CoverageManager{
		coverageCache:         make(map[uint64]string),
		coverageInfoMap:       make(map[string][]int),
		coverageHistory:       make(map[time.Time]int),
		lastMaxCoverage:       0,
		addressToLineFunction: processingFunction,
	}
}
