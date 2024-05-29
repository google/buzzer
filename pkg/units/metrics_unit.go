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
	"sync"
	"time"

	fpb "buzzer/proto/ffi_go_proto"
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

	metricsCollection *MetricsCollection
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
		_, err := mu.metricsCollection.coverageManager.ProcessCoverageAddresses(vres.GetCoverageAddress())
		if err != nil {
			fmt.Printf("%q\n", err)
		}
		mu.metricsCollection.processVerifierLog(vres)
	}
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
func NewMetricsUnit(threshold int, kcovSize uint64, vmLinuxPath, sourceFilesPath, metricsServerAddr string, metricsServerPort uint16, cm *CoverageManager) *Metrics {
	mc := &MetricsCollection{
		coverageManager:  cm,
		verifierVerdicts: make(map[string]int),
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
		metricsCollection: mc,
		metricsServer:     ms,
	}
	mu.init()
	go mu.validationResultProcessingRoutine()
	go ms.serve()
	return mu
}
