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

// Package oracle is a set of abstractions for tracking the state of register sets
// at different offsets in an eBPF program.
package oracle

import (
	"errors"

	"buzzer/pkg/ebpf/ebpf"
)

// RegisterState holds the best known state of a particular register
// at a particular point in time.
type RegisterState struct {
	Known bool
	Value uint64
}

// RegisterSet is a fixed set of RegisterStates used to model the full
// collection of registers in the VM.
type RegisterSet [ebpf.RegisterCount]RegisterState

// RegisterOracle is used to track the states of various registers
// at particular offsets in the program at a specific point in time.
type RegisterOracle struct {
	state map[int32]*RegisterSet
}

// LookupRegValue looks up the given register number at the given program offset.
// Similar to map lookups, a (value, ok) tuple is returned where the `value` is
// only valid if `ok` is `true`.
func (r *RegisterOracle) LookupRegValue(offset int32, register uint8) (uint64, bool, error) {
	if int(register) > ebpf.RegisterCount {
		return 0, false, errors.New("given register is larger than register set size")
	}

	regSet, ok := r.state[offset]
	if !ok {
		return 0, false, nil
	}

	return regSet[register].Value, regSet[register].Known, nil
}

// SetRegValue sets the given register number at the given program offset.
func (r *RegisterOracle) SetRegValue(offset int32, register uint8, value uint64) error {
	if int(register) > ebpf.RegisterCount {
		return errors.New("given register is larger than register set size")
	}

	regSet, ok := r.state[offset]
	if !ok {
		regSet = new(RegisterSet)
		r.state[offset] = regSet
	}
	regSet[register].Known = true
	regSet[register].Value = value

	return nil
}

// NewRegisterOracle creates a new instance of the oracle with offset 0 set
// to an uninitialized register set.
func NewRegisterOracle() *RegisterOracle {
	oracle := new(RegisterOracle)
	oracle.state = make(map[int32]*RegisterSet)
	return oracle
}
