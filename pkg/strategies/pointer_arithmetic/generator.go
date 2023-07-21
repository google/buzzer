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
)

// Generator is responsible for constructing the ebpf for this strategy.
type Generator struct {
	instructionCount int
	magicNumber      int32
}

func (g *Generator) generateHeader(prog *Program) Instruction {
	var root, ptr Instruction
	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := GetRegisterFromNumber(uint8(i))
		regVal := int32(prog.GetRNG().RandInt())
		nextInstr := MovRegImm64(reg, regVal)
		if ptr != nil {
			ptr.SetNextInstruction(nextInstr)
		}
		if root == nil {
			root = nextInstr
		}
		ptr = nextInstr
		prog.MarkRegisterInitialized(reg.RegisterNumber())
	}
	return root
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree.
func (g *Generator) GenerateNextInstruction(prog *Program) Instruction {
	// We reached the number of instructions we were told to generate.
	if g.instructionCount == 0 {
		return g.generateProgramFooter(prog)
	}
	g.instructionCount--

	var instr Instruction

	// Generate about 40% of instructions as jumps.
	if prog.GetRNG().RandRange(1, 100) <= 60 {
		instr = GenerateRandomAluInstruction(prog)
	} else {
		falseBranchGenerator := func(a *Program) (Instruction, int16) {
			// 20 is an arbitrary number here.
			operationQuantity := int16(20)
			root := GenerateRandomAluInstruction(prog)
			ptr := root
			for i := int16(1); i < operationQuantity; i++ {
				next := GenerateRandomAluInstruction(prog)
				ptr.SetNextInstruction(next)
				ptr = next
			}
			return root, operationQuantity
		}
		instr = GenerateRandomJmpRegInstruction(prog, g.GenerateNextInstruction, falseBranchGenerator)
	}
	instr.GenerateNextInstruction(prog)
	return instr
}

func (g *Generator) generateProgramFooter(prog *Program) Instruction {
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
	chosenReg, _ := GetRegisterFromNumber(prog.GetRandomRegister())
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
func (g *Generator) Generate(prog *Program) Instruction {
	root := g.generateHeader(prog)
	root.SetNextInstruction(g.GenerateNextInstruction(prog))
	return root
}
