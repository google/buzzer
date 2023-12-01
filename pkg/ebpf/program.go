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

// Package ebpf implements all the logic to deal with the generation of ebpf
// programs.
package ebpf

//#include <linux/bpf.h>
//#include <stdlib.h>
//int create_bpf_map(size_t size);
//void close_fd(int fd);
import "C"

// Program represents a sequence of instructions of an ebpf program.
import (
	"buzzer/pkg/rand"
	"errors"
)

// Program represents a generated instance of an eBPF Program. This data structure
// exists mostly to keep track of the state of an eBPF program and to export methods
// that the generator can use to interact with the program.
type Program struct {
	// Keep track of which registers have been initialized so we can use
	// them for other operations without the verifier complaining.
	trackedRegs []uint8

	// File descriptor for the eBPF map used to store value results.
	logMap int

	// MapSize Number of max elements on the ebpf map.
	MapSize int

	// MinRegister Minimum register number that can be used for random
	// alu operations.
	MinRegister uint8

	// MaxRegister Maximum register number that can be used for random
	// alu operations.
	MaxRegister uint8

	// Instructions corresponding to this ebpf program.
	Instructions []Instruction
}

// GenerateBytecode returns the bytecode array associated with this ebpf
// program.
func (a *Program) GenerateBytecode() []uint64 {
	r := []uint64{}
	for _, i := range a.Instructions {
		r = append(r, i.GenerateBytecode()...)
	}
	return r
}

// LogMap returns the internal log map fd.
func (a *Program) LogMap() int {
	return a.logMap
}

// IsRegisterInitialized can be used by the generation algorithm to pick source
// registers that have been initialized.
func (a *Program) IsRegisterInitialized(regNo uint8) bool {
	for _, reg := range a.trackedRegs {
		if regNo == reg {
			return true
		}
	}
	return false
}

// GetRandomRegister returns a random register that has been initialized in the pprog.
func (a *Program) GetRandomRegister() uint8 {
	if len(a.trackedRegs) == 0 {
		return 0xFF
	}

	reg := a.trackedRegs[rand.SharedRNG.RandRange(0, uint64(len(a.trackedRegs)-1))]
	for !(reg >= a.MinRegister && reg <= a.MaxRegister) {
		reg = a.trackedRegs[rand.SharedRNG.RandRange(0, uint64(len(a.trackedRegs)-1))]
	}
	return reg
}

// MarkRegisterInitialized adds `reg` to the list of registers that have been
// initialized.
func (a *Program) MarkRegisterInitialized(reg uint8) {
	if !(reg >= a.MinRegister && reg <= a.MaxRegister) {
		return
	}
	a.trackedRegs = append(a.trackedRegs, reg)
}

// Cleanup frees the map resources of this tree.
func (a *Program) Cleanup() {
	C.close_fd(C.int(a.logMap))
}

// GeneratePoc generates a c program that represents this ebpf program.
func (a *Program) GeneratePoc() error {
	return GeneratePoc(a)
}

// SetInstructions assigns the given instruction array to the program.
func (a *Program) SetInstructions(i []Instruction) {
	a.Instructions = i
}

// New creates a new prog with the given generator.
func New(mapSize int, minReg, maxReg uint8) (*Program, error) {
	lMap := int(C.create_bpf_map(C.ulong(mapSize)))
	if lMap < 0 {
		return nil, errors.New("Could not create log map for the program")
	}
	prog := &Program{
		logMap:       lMap,
		MapSize:      mapSize,
		MinRegister:  minReg,
		MaxRegister:  maxReg,
		trackedRegs:  []uint8{},
		Instructions: []Instruction{},
	}
	return prog, nil
}
