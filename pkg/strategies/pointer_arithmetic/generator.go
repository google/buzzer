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

package pointerarithmetic

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/rand"
)

// Generator is responsible for constructing the ebpf for this strategy.
type Generator struct {
	instructionCount int
	magicNumber      int32
}

func (g *Generator) generateHeader(prog *Program) []Instruction {
	var root []Instruction
	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := GetRegisterFromNumber(uint8(i))
		regVal := int32(rand.SharedRNG.RandInt())
		root = append(root, Mov64(reg, regVal))
		prog.MarkRegisterInitialized(reg.RegisterNumber())
	}
	return root
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree.
func (g *Generator) generateBody() []Instruction {
	body := []Instruction{}	
	for i:= 0; i < g.instructionCount; i++ {
		// Generate about 60% of instructions as alu instructions, the rest as jumps.
		if rand.SharedRNG.RandRange(0,100) <= 60 {
			body = append(body, RandomAluInstruction())
		} else {
			// The parameter to RandomJmpInstruction is the maximum offset to have
			// this is to prevent out of bounds jumps.
			body = append(body, RandomJmpInstruction(uint64(10)))
		}
	}
	return body
}

func (g *Generator) generateFooter(prog *Program) []Instruction {
	// The generated footer does the following:
	// 1) Loads a register with a pointer to a map.
	// 2) Chooses a random register.
	// 3) Compute an address using the map pointer and random register,
	//    i.e. `map_fd + register`.
	// 4) Writes a magic number to the location at the calculated address.
	// 5) Writes a magic number to the next map element.
	//
	// If control flow makes it to (5) *and* the map element written in (5)
	// is non-zero, then the generated program was verified correct and
	// executed.
	chosenReg, _ := GetRegisterFromNumber(uint8(rand.SharedRNG.RandRange(6,9)))
	root, _ := InstructionSequence(
		Mov64(RegR0, 0),
		StW(RegR10, RegR0, -4),
		LdMapByFd(RegR4, prog.LogMap()),
		Mov64(RegR1, RegR4),
		Mov64(RegR2, RegR10),
		Add64(RegR2, -4),
		Call(MapLookup),
		JmpNE(RegR0, 0, 1),
		Exit(),
		Add64(RegR0, chosenReg),
		StDW(RegR0, g.magicNumber, 0),

		// Repeat, no ptr arithmetic.
		Mov64(RegR0, 1),
		StW(RegR10, RegR0, -4),
		LdMapByFd(RegR4, prog.LogMap()),
		Mov64(RegR1, RegR4),
		Mov64(RegR2, RegR10),
		Add64(RegR2, -4),
		Call(MapLookup),
		JmpNE(RegR0, 0, 1),
		Exit(),
		StDW(RegR0, g.magicNumber, 0),
		Mov64(RegR0, 0),
		Exit(),
	)

	return root
}

// Generate is the main function that builds the ebpf for this strategy.
func (g *Generator) Generate(prog *Program) []Instruction {
	root := g.generateHeader(prog)
	root = append(root, g.generateBody()...)
	root = append(root, g.generateFooter(prog)...)
	return root
}
