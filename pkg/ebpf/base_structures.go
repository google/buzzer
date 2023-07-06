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

package ebpf

import (
	"fmt"
	"strconv"
)

// EBPFOperation represents a single, high-level EBPF operation such as an ALU operation,
// a conditional or function call
type Operation interface {
	GenerateBytecode() []uint64
	GenerateNextInstruction(prog *Program)
	SetNextInstruction(next Operation)
	GetNextInstruction() Operation
	NumerateInstruction(instrNo uint32) int
	GeneratePoc() []string
}

// Register represents an eBPF register, declared as a struct to differentiate
// a register value from an immediate constant value.
type Register struct {
	registerNumber uint8
}

// Returns the string representation of the register to be used on PoC
// generation.
func (r *Register) ToString() string {
	return "BPF_REG_" + strconv.Itoa(int(r.registerNumber))
}

// RegisterNumber is the associated number to a register object.
func (r *Register) RegisterNumber() uint8 {
	return r.registerNumber
}

func GetRegisterFromNumber(regNo uint8) (*Register, error) {
	switch regNo {
	case 0:
		return RegR0, nil
	case 1:
		return RegR1, nil
	case 2:
		return RegR2, nil
	case 3:
		return RegR3, nil
	case 4:
		return RegR4, nil
	case 5:
		return RegR5, nil
	case 6:
		return RegR6, nil
	case 7:
		return RegR7, nil
	case 8:
		return RegR8, nil
	case 9:
		return RegR9, nil
	case 10:
		return RegR10, nil
	default:
		return nil, fmt.Errorf("unknonw register value %d", regNo)
	}
}
