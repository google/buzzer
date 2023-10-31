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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	fpb "buzzer/proto/ebpf_fuzzer_go_proto"
)

// Metrics is the central place where the fuzzer can report any metrics
// or statistics. It is also responsible for refining coverage in an async way.
// (Coverage refine is an expensive operation, so we do it async).
type Metrics struct {
	// SamplingThreshold represents the number of samples that will be
	// skipped before detailed info is collected.
	//
	// e.g. if SamplingThreshol = 100; then every 100th sample passed through
	// the Metrics will collect detailed info (coverage, and verifier logs).
	SamplingThreshold int

	// KCovSize represents the size of the coverage sample that kcov will
	// collect, the bigger the sample the slower collecting coverage
	// will be (but the more precies).
	KCovSize uint64

	isKCovSupported bool

	// Since Processing coverage is a slow operation, we put all the
	// coverage data in a queue to be processed by a separate goroutine.
	validationResultQueue []*fpb.ValidationResult

	// Protects the validation queue.
	validationMutex sync.Mutex

	// Path where the vm linux image lives, it will be passed to addr2line
	vmLinuxPath string

	coverageCache map[uint64]bool

	metricsCollection *Collection
	metricsServer     *MetricsServer
}

func (mu *Metrics) enqueueValidationResult(vr *fpb.ValidationResult) {
	mu.validationMutex.Lock()
	defer mu.validationMutex.Unlock()

	mu.validationResultQueue = append(mu.validationResultQueue, vr)
}

func (mu *Metrics) dequeueValidationResult() *fpb.ValidationResult {
	mu.validationMutex.Lock()
	defer mu.validationMutex.Unlock()

	if len(mu.validationResultQueue) == 0 {
		return nil
	}

	res := mu.validationResultQueue[0]

	// Remove the top element of the queue.
	if len(mu.validationResultQueue) == 1 {
		mu.validationResultQueue = []*fpb.ValidationResult{}
	} else {
		mu.validationResultQueue = mu.validationResultQueue[1:]
	}

	return res
}

func (mu *Metrics) validationResultProcessingRoutine() {
	for {
		vres := mu.dequeueValidationResult()
		if vres == nil {
			time.Sleep(1 * time.Second)
			continue
		}
		err := mu.processCoverage(vres.GetCoverageAddress())
		if err != nil {
			fmt.Printf("%q\n", err)
		}
	}
}

func (mu *Metrics) processCoverage(cov []uint64) error {
	unknownAddr := []uint64{}
	for _, address := range cov {
		if _, ok := mu.coverageCache[address]; !ok {
			unknownAddr = append(unknownAddr, address)
		}
	}

	if len(unknownAddr) == 0 {
		return nil
	}

	stdInStr := ""
	for _, ukAddr := range unknownAddr {
		stdInStr += fmt.Sprintf("%02x\n", ukAddr)
	}
	cmd := exec.Command("/usr/bin/addr2line", "-e", mu.vmLinuxPath)
	w, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	w.Write([]byte(stdInStr))
	w.Close()
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	outString := string(out)
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
			return err
		}
		fullPath := strings.Split(cleanedLine, ":")[0]

		mu.coverageCache[unknownAddr[i]] = true
		mu.metricsCollection.recordCoverageLine(fileName, fullPath, lineNumber)
	}
	return nil
}

// ShouldGetCoverage has two purposes: record that a program is about
// to be passed by the verifier and return if the metrics unit wants to
// collect coverage information on it.
func (mu *Metrics) ShouldGetCoverage() (bool, uint64) {
	mu.metricsCollection.recordVerifiedProgram()
	if !mu.isKCovSupported {
		return false, 0
	}

	if !mu.shouldCollectDetailedInfo() {
		return false, 0
	}
	return mu.isKCovSupported, mu.KCovSize
}

func (mu *Metrics) shouldCollectDetailedInfo() bool {
	return mu.metricsCollection.getProgramsVerified()%mu.SamplingThreshold == 0
}

// RecordVerificationResults collects metrics from the provided
// verification result proto.
func (mu *Metrics) RecordVerificationResults(vr *fpb.ValidationResult) {
	if vr.GetIsValid() {
		mu.metricsCollection.recordValidProgram()
	}

	if !mu.shouldCollectDetailedInfo() {
		return
	}

	if !vr.GetDidCollectCoverage() {
		return
	}

	mu.enqueueValidationResult(vr)
}

func (mu *Metrics) init() {
	if _, err := os.Stat("/sys/kernel/debug/kcov"); errors.Is(err, os.ErrNotExist) {
		mu.isKCovSupported = false
	} else {
		mu.isKCovSupported = true
	}
}

// NewMetricsUnit Creates a new Central Metrics Unit.
func NewMetricsUnit(threshold int, kcovSize uint64, vmLinuxPath, sourceFilesPath, metricsServerAddr string, metricsServerPort uint16) *Metrics {
	mc := &Collection{
		coverageInfoMap: make(map[string]*coverageInfo),
	}
	ms := &MetricsServer{
		host:              metricsServerAddr,
		port:              metricsServerPort,
		filePath:          sourceFilesPath,
		metricsCollection: mc,
	}
	mu := &Metrics{
		SamplingThreshold: threshold,
		KCovSize:          kcovSize,
		coverageCache:     make(map[uint64]bool),
		metricsCollection: mc,
		metricsServer:     ms,
		vmLinuxPath:       vmLinuxPath,
	}
	mu.init()
	go mu.validationResultProcessingRoutine()
	go ms.serve()
	return mu
}
