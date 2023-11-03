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

	fpb "buzzer/proto/ebpf_fuzzer_go_proto"
)

func TestMetrics(t *testing.T) {
	expectedKcovSize := uint64(42)
	cm := &CoverageManagerImpl{
		coverageCache:   make(map[uint64]string),
		coverageInfoMap: make(map[string][]int),
		addressToLineFunction: func(inputString string) (string, error) {
			return "", nil
		},
	}
	metricsCollection := &MetricsCollection{
		coverageManager: cm,
	}

	metricsUnit := Metrics{
		SamplingThreshold: 1,
		KCovSize:          expectedKcovSize,
		isKCovSupported:   true,
		metricsCollection: metricsCollection,
	}

	isKCovSupported, kCovSize := metricsUnit.ShouldGetCoverage()
	if !isKCovSupported {
		t.Errorf("isKCovSupported = %v, want = true", isKCovSupported)
	}

	if kCovSize != expectedKcovSize {
		t.Errorf("kCovSize = %d, want = %d", kCovSize, expectedKcovSize)
	}

	if metricsUnit.metricsCollection.programsVerified != 1 {
		t.Errorf("metrics unit did not advance the quantity of programs verified")
	}

	vr := &fpb.ValidationResult{
		IsValid:            true,
		DidCollectCoverage: true,
	}
	metricsUnit.RecordVerificationResults(vr)
	if metricsUnit.metricsCollection.validPrograms != 1 {
		t.Errorf("metrics unit did not advance the quantity of valid programs")
	}

	if len(metricsUnit.validationResultQueue) != 1 {
		t.Errorf("len(metricsUnit.validationResultQueue) = %d, want %d", len(metricsUnit.validationResultQueue), 1)
	}
}
