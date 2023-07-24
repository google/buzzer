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

package stackcorruption

import (
	. "buzzer/pkg/ebpf/ebpf"
)

// Generator is responsible for constructing the ast for this strategy.
type Generator struct{
	instructionCount int
	magicNumber		int
	skbOffset		int16
	mapPtrOffset	int16
	mapFirstElementOffset int16
	skbReadOffset   int16
}

// Generates the first set of instructions of the program.
func (g *Generator) generateHeader(prog *Program) Instruction {
	g.instructionCount = int(prog.GetRNG().RandRange(50, 100))
	g.skbOffset = -8
	g.mapPtrOffset = -16
	g.mapFirstElementOffset = -24
	g.skbReadOffset = -32
	root, _ := InstructionSequence(
		// Backup the skb pointer.
		StDW(RegR10, RegR1, g.skbOffset),
		LdMapByFd(RegR0, prog.LogMap()),
		StDW(RegR10, RegR0, g.mapPtrOffset),
		LdMapElement(RegR0, 0, RegR10, -20),
		JmpNE(RegR0, 0, 1),
		Exit(),
		StDW(RegR10, RegR0, g.mapFirstElementOffset),
		StDW(RegR10, 0, g.skbReadOffset),
	)

	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := GetRegisterFromNumber(uint8(i))
		var instr Instruction
		if prog.GetRNG().RandRange(1, 10) < 7 {
			instr, _ = InstructionSequence(
				LdDW(reg, RegR0, 0),
				Add64(reg, int32(prog.GetRNG().RandInt())),
			)
		} else {
			instr, _ = InstructionSequence(
				Mov64(reg, int32(prog.GetRNG().RandInt())),
			)
		}
		prog.MarkRegisterInitialized(i)
		root.SetNextInstruction(instr)
	}
	return root
}

func (g *Generator) randomAlu(prog *Program) Instruction {
	return GenerateRandomAluInstruction(prog)
}

func (g *Generator) randomJmp(prog *Program) Instruction {
	falseBranchGenerator := func(prog *Program) (Instruction, int16) {
		operationQuantity := int16(prog.GetRNG().RandRange(1, 10))
		instructions := []Instruction{}
		for i := int16(0); i < operationQuantity; i++ {
			instructions = append(instructions, GenerateRandomAluInstruction(prog))
		}
		root, _ := InstructionSequence(instructions...)
		return root, operationQuantity
	}
	return GenerateRandomJmpRegInstruction(prog, g.GenerateNextInstruction, falseBranchGenerator)
}

func (g *Generator) skbCall(prog *Program) Instruction {
    source, _ := GetRegisterFromNumber(prog.GetRandomRegister())
	corruptingSnippet, _ := InstructionSequence(
		JmpLT(source, 1, 1),
		Mov64(source, 1),
		Add64(source, 1),
		LdDW(RegR1, RegR10, g.skbOffset),
		CallSkbLoadBytesRelative(RegR1, 0, RegR10, g.skbReadOffset, source, 1),
		Mov(RegR1, 0x0FFFFFFF),
	)
	return corruptingSnippet
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree
func (g *Generator) GenerateNextInstruction(prog *Program) Instruction {
	g.instructionCount -= 1
	if (g.instructionCount == 0) {
		return g.generateProgramFooter(prog)
	}

	var instr Instruction

	coinToss := prog.GetRNG().RandRange(1, 100)

	if coinToss <= 65 {
		instr = g.randomJmp(prog)
	} else {
		instr = g.randomAlu(prog)
	}

	instr.GenerateNextInstruction(prog)
	return instr
}

// Generate is the main function that builds the ast for this strategy.
func (g *Generator) Generate(prog *Program) Instruction {
	header := g.generateHeader(prog)
	header.SetNextInstruction(g.GenerateNextInstruction(prog))
	return header
}

func (g *Generator) generateProgramFooter(p *Program) Instruction {
	sequence := g.skbCall(p)
	footer, _ := InstructionSequence(
		LdDW(RegR0, RegR10, g.mapFirstElementOffset),
		StDW(RegR0, g.magicNumber, 0),
		LdDW(RegR0, RegR10, g.mapPtrOffset),
		LdMapElement(RegR0, 1, RegR10, -36),
		JmpNE(RegR0, 0, 1),
		Exit(),
		StDW(RegR0, g.magicNumber, 0),
		LdDW(RegR0, RegR10, g.mapPtrOffset),
		LdMapElement(RegR0, 2, RegR10, -36),
		JmpNE(RegR0, 0, 1),
		Exit(),
		LdDW(RegR1, RegR10, g.skbReadOffset),
		StDW(RegR0,RegR1, 0),
		Mov64(RegR0, 0),
		Exit(),
	)
	sequence.SetNextInstruction(footer)
	return sequence
}
