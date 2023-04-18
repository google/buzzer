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
	"log"
	"flag"

	"buzzer/pkg/metrics/metrics"
	"buzzer/pkg/units/units"
)

// Flags that the binary can accept.
var (
	runMode            = flag.String("run_mode", "standalone", "Mode to run the fuzzer. Possible values are: server, client, standalone (default: Standalone)")
	fuzzStrat          = flag.String("fuzzing_strategy", "parse_verifier_log", "Strategy to use to fuzz ebpf")
	coverageBufferSize = flag.Uint64("coverage_buffer_size", 64<<20, "Size of the buffer passed to kcov to get coverage addresses, the higher the number, the slower coverage collection will be")
	metricsThreshold   = flag.Int("metrics_threshold", 200, "Collect detailed metrics (coverage) every `metrics_threshold` validated programs")
	vmLinuxPath        = flag.String("vmlinux_path", "/root/vmlinux", "Path to the linux image that will be passed to addr2line to get coverage info")
	sourceFilesPath    = flag.String("src_path", "/root/sourceFiles", "The fuzzer will look for source files to visualize the coverage at this path")
	metricsServerAddr  = flag.String("metrics_server_addr", "0.0.0.0", "Address that the metrics server will listen to at")
	metricsServerPort  = flag.Uint("metrics_server_port", 8080, "Port that the metrics server will listen to at")
	verbosity          = flag.Int("verbosity_level", 0, "How verbose the binary behaves. Possible values are: 0, 1, 2. Where 0 is quiet mode and 2 is the most verbose mode (default = 0)")
	localIP            = flag.String("local_ip", "", "Address to which bind the Registry/Execution server depending on whether the binary runs in server or client mode")
	localPort          = flag.Uint("local_port", 4444, "Port at which the local Registry/Execution server will listen at (default = 4444)")
	remoteIP           = flag.String("remote_ip", "", "If run in client mode, this ip will be used to contact the server")
	remotePort         = flag.Uint("remote_port", 4444, "Which port is the server running in case of client mode, or which port should the server run in case of server mode (default = 4444)")
)

func main() {
	flag.Parse()
	controlUnit := units.ControlUnit{}
	metricsUnit := metrics.New(*metricsThreshold, *coverageBufferSize, *vmLinuxPath, *sourceFilesPath, *metricsServerAddr, uint16(*metricsServerPort))
	if err := controlUnit.Init(&units.Executor{
		MetricsUnit: metricsUnit,
	}, *runMode, *fuzzStrat,
		*verbosity, *localIP, *localPort, *remoteIP, *remotePort); err != nil {
		log.Fatalf("failed to init control unit: %v", err)
	}

	if err := controlUnit.RunFuzzer(); err != nil {
		log.Fatalf("failed to init control unit: %v", err)
	}
}
