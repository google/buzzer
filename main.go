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

// package main creates the executable for the fuzzer.
package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"

	"buzzer/pkg/strategies/strategies"
	"buzzer/pkg/units/units"
)

// Flags that the binary can accept.
var (
	coverageBufferSize = flag.Uint64("coverage_buffer_size", 64<<20, "Size of the buffer passed to kcov to get coverage addresses, the higher the number, the slower coverage collection will be")
	metricsThreshold   = flag.Int("metrics_threshold", 200, "Collect detailed metrics (coverage) every `metrics_threshold` validated programs")
	strategyName       = flag.String("strategy", "playground", "Strategy to use for fuzzing")
	vmLinuxPath        = flag.String("vmlinux_path", "/root/vmlinux", "Path to the linux image that will be passed to addr2line to get coverage info")
	sourceFilesPath    = flag.String("src_path", "/root/sourceFiles", "The fuzzer will look for source files to visualize the coverage at this path")
	metricsServerAddr  = flag.String("metrics_server_addr", "0.0.0.0", "Address that the metrics server will listen to at")
	metricsServerPort  = flag.Uint("metrics_server_port", 8080, "Port that the metrics server will listen to at")
)

var (
	strats = []units.Strategy{
		strategies.NewPointerArithmeticStrategy(),
		strategies.NewPlaygroundStrategy(),
		strategies.NewCoverageBasedStrategy(),
		strategies.NewCbpfPlaygroundStrategy(),
		strategies.NewCbpfRandomInstructionStrategy(),
	}
)

func main() {
	flag.Parse()
	var strategy units.Strategy = nil
	for _, s := range strats {
		if s.Name() == *strategyName {
			strategy = s
			break
		}
	}
	if strategy == nil {
		fmt.Printf("Invalid strategy name %s, available strategies are: \n", *strategyName)
		for _, s := range strats {
			fmt.Printf("\t - %s\n", s.Name())
		}
		return
	}
	fmt.Printf("using strategy %s\n", strategy.Name())
	coverageManager := units.NewCoverageManager(func(inputString string) (string, error) {
		cmd := exec.Command("/usr/bin/addr2line", "-e", *vmLinuxPath)
		w, err := cmd.StdinPipe()
		if err != nil {
			return "", err
		}
		w.Write([]byte(inputString))
		w.Close()
		outBytes, err := cmd.Output()
		return string(outBytes), err
	})

	controlUnit := units.Control{}
	metricsUnit := units.NewMetricsUnit(*metricsThreshold, *coverageBufferSize, *vmLinuxPath, *sourceFilesPath, *metricsServerAddr, uint16(*metricsServerPort), coverageManager)

	if err := controlUnit.Init(&units.FFI{
		MetricsUnit: metricsUnit,
	}, coverageManager, strategy); err != nil {
		log.Fatalf("failed to init control unit: %v", err)
	}

	if err := controlUnit.RunFuzzer(); err != nil {
		log.Fatalf("failed to init control unit: %v", err)
	}
}
