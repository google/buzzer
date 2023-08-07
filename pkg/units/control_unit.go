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

// Package units implements the business logic to make the fuzzer work
package units

import (
	"fmt"

	"buzzer/pkg/strategies/parse_verifier/parseverifier"
	"buzzer/pkg/strategies/playground/playground"
	"buzzer/pkg/strategies/pointer_arithmetic/pointerarithmetic"
	"buzzer/pkg/strategies/stack_corruption/stackcorruption"
	"buzzer/pkg/strategies/strategies"
)

// RunMode are the modes of operation for the server.
type RunMode string

const (
	// Server indicates that the binary will generate ebpf programs to
	// execute in the registered clients.
	Server RunMode = "server"

	// Client Means that the binary will wait for incoming ebpf programs,
	// execute them and then send the results report back to the server.
	Client = "client"

	// Standalone means that the binary will generate and execute ebpf
	// programs locally, without any network communications with other
	// binaries.
	Standalone = "standalone"
)

// VerbosityLevel indicates how verbose the binary behaves.
type VerbosityLevel int

const (
	// Quiet mode makes the binary not log anything.
	Quiet VerbosityLevel = 0

	// Info mode makes the binary just print some relevant information.
	Info = 1

	// Verbose gives the most information on what is happening on the binary.
	Verbose = 2
)

// StrategyInterface contains all the methods that a fuzzing strategy should
// implement.
type StrategyInterface interface {
	Fuzz(e strategies.ExecutorInterface) error
}

// ControlUnit directs the execution of the fuzzer.
type ControlUnit struct {
	strat      StrategyInterface
	ex         strategies.ExecutorInterface
	rm         RunMode
	vl         VerbosityLevel
	localIP    string
	localPort  uint
	remoteIP   string
	remotePort uint
	rdy        bool
}

// Init prepares the control unit to be used.
func (cu *ControlUnit) Init(executor strategies.ExecutorInterface, runMode, fuzzStrategyFlag string, verbosity int, localIP string, localPort uint, remoteIP string, remotePort uint) error {
	cu.ex = executor

	cu.localIP = localIP
	cu.localPort = localPort

	cu.remoteIP = remoteIP
	cu.remotePort = remotePort

	switch runMode {
	case "server":
		cu.rm = Server
	case "client":
		cu.rm = Client
	case "standalone":
		cu.rm = Standalone
	default:
		return fmt.Errorf("unknown run mode: %s", runMode)
	}

	switch verbosity {
	case 0:
		cu.vl = Quiet
	case 1:
		cu.vl = Info
	case 2:
		cu.vl = Verbose
	default:
		return fmt.Errorf("unknown verbosity level: %d", verbosity)
	}

	switch fuzzStrategyFlag {
	case parseverifier.StrategyName:
		cu.strat = &parseverifier.StrategyParseVerifierLog{}
	case pointerarithmetic.StrategyName:
		cu.strat = &pointerarithmetic.Strategy{
			// 60 is an arbitrary number.
			InstructionCount: 60,
		}
	case playground.StrategyName:
		cu.strat = &playground.Strategy{}
	case stackcorruption.StrategyName:
		cu.strat = &stackcorruption.Strategy{}
	default:
		return fmt.Errorf("unknown fuzzing strategy: %s", fuzzStrategyFlag)
	}

	cu.rdy = true
	return nil
}

// IsReady indicates to the caller if the ControlUnit is initialized successully.
func (cu *ControlUnit) IsReady() bool {
	return cu.rdy
}

// GetRunMode returns the current run mode for the binary.
func (cu *ControlUnit) GetRunMode() RunMode {
	return cu.rm
}

// GetVerbosityLevel returns the current verbosity level for the binary.
func (cu *ControlUnit) GetVerbosityLevel() VerbosityLevel {
	return cu.vl
}

// RunFuzzer kickstars the fuzzer in the mode that was specified at Init time.
func (cu *ControlUnit) RunFuzzer() error {
	switch cu.rm {
	case Server:
		return cu.runServerMode()
	case Client:
		return cu.runClientMode()
	case Standalone:
		return cu.runStandaloneMode()
	default:
		return fmt.Errorf("unknown run mode")
	}
}

// The binary will do the following:
// - Generate ebpf programs
// - Distribute them to the clients that have registered thus far
// - Collect all the run results and present them in a report
func (cu *ControlUnit) runServerMode() error {
	// TODO: Implement this method.
	return fmt.Errorf("running buzzer in server mode is not implemented yet")
}

// The binary will do the following:
// - Register with the server
// - Await for incoming ebpf programs and execute them
// - Send the execution results back to the server
func (cu *ControlUnit) runClientMode() error {
	// TODO:Implement this method.
	return fmt.Errorf("running buzzer in client mode is not implemented yet")
}

// The binary will do the following:
// - Generate ebpf programs
// - Run them locally and report the execution results
func (cu *ControlUnit) runStandaloneMode() error {
	return cu.strat.Fuzz(cu.ex)
}
