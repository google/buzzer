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

// Instruction represents a single, high-level EBPF instruction such as an ALU instruction,
// a conditional or function call
type Instruction interface {
	GenerateBytecode() []uint64
	GenerateNextInstruction(prog *Program)
	SetNextInstruction(next Instruction)
	GetNextInstruction() Instruction
	NumerateInstruction(instrNo uint32) int
	GeneratePoc() []string
}

// BaseInstruction groups together logic that is common to all eBPF instruction
// representations.
type BaseInstruction struct {
	instructionNumber uint32
	Opcode            uint8
	InstructionClass  uint8
	nextInstruction   Instruction
}

// GenerateNextInstruction generates the next instruction.
func (i *BaseInstruction) GenerateNextInstruction(ast *Program) {
	if i.nextInstruction != nil {
		i.nextInstruction.GenerateNextInstruction(ast)
	} else {
		i.nextInstruction = ast.Gen.GenerateNextInstruction(ast)
	}
}

// NumerateInstruction sets the current instruction number.
func (i *BaseInstruction) NumerateInstruction(instrNo uint32) int {
	i.instructionNumber = instrNo
	if i.nextInstruction != nil {
		return 1 + i.nextInstruction.NumerateInstruction(instrNo+1)
	}
	return 1
}

// SetNextInstruction manually sets the next instruction.
func (i *BaseInstruction) SetNextInstruction(next Instruction) {
	if i.nextInstruction != nil {
		i.nextInstruction.SetNextInstruction(next)
	} else {
		i.nextInstruction = next
	}
}

// GetNextInstruction returns the next instruction, mostly used for testing
// purposes.
func (i *BaseInstruction) GetNextInstruction() Instruction {
	return i.nextInstruction
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
