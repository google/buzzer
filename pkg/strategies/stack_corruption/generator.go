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
	"buzzer/pkg/rand"
)

// Generator is responsible for constructing the ast for this strategy.
type Generator struct {
	instructionCount      int
	magicNumber           int
	skbOffset             int16
	mapPtrOffset          int16
	mapFirstElementOffset int16
	skbReadOffset         int16
}

// Generates the first set of instructions of the program.
func (g *Generator) generateHeader(prog *Program) []Instruction {
	g.instructionCount = int(rand.SharedRNG.RandRange(50, 100))
	g.skbOffset = -8
	g.mapPtrOffset = -16
	g.mapFirstElementOffset = -24
	g.skbReadOffset = -32
	root, _ := InstructionSequence(
		// Backup the skb pointer.
		StDW(RegR10, RegR1, g.skbOffset),
		LdMapByFd(RegR0, prog.LogMap()),
		StDW(RegR10, RegR0, g.mapPtrOffset),
		
	)
	ldMapElement, _ := LdMapElement(RegR0, 0, RegR10, -20)
	root = append(root, ldMapElement...)
	rest, _ := InstructionSequence(
		JmpNE(RegR0, 0, 1),
		Exit(),
		StDW(RegR10, RegR0, g.mapFirstElementOffset),
		StDW(RegR10, 0, g.skbReadOffset),
	)
	root = append(root, rest...)

	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := GetRegisterFromNumber(uint8(i))
		var instr []Instruction
		if rand.SharedRNG.OneOf(7) {
			instr, _ = InstructionSequence(
				LdDW(reg, RegR0, 0),
				Add64(reg, int32(rand.SharedRNG.RandInt())),
			)
		} else {
			instr, _ = InstructionSequence(
				Mov64(reg, int32(rand.SharedRNG.RandInt())),
			)
		}
		prog.MarkRegisterInitialized(i)
		root = append(root, instr...)
	}
	return root
}

func (g *Generator) skbCall(prog *Program) []Instruction {
	source, _ := GetRegisterFromNumber(prog.GetRandomRegister())
	corruptingSnippet, _ := InstructionSequence(
		JmpLT(source, 1, 1),
		Mov64(source, 1),
		Add64(source, 1),
		LdDW(RegR1, RegR10, g.skbOffset),
	)

	callskb, _ := CallSkbLoadBytesRelative(RegR1, 0, RegR10, g.skbReadOffset, source, 1)
	corruptingSnippet = append(corruptingSnippet, callskb...)
	corruptingSnippet = append(corruptingSnippet, Mov(RegR1, 0x0FFFFFFF))
	return corruptingSnippet
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree
func (g *Generator) generateBody() []Instruction {
	body := []Instruction{}
	for i := 0; i < g.instructionCount; i++ {
		if rand.SharedRNG.OneOf(65) {
			body = append(body, RandomJmpInstruction(uint64(g.instructionCount - i)))
		} else {
			body = append(body, RandomAluInstruction())
		}
	}
	return body
}

// Generate is the main function that builds the ast for this strategy.
func (g *Generator) Generate(prog *Program) []Instruction {
	program := g.generateHeader(prog)
	program = append(program, g.generateBody()...)
	program = append(program, g.generateFooter(prog)...)
	return program
}

func (g *Generator) generateFooter(p *Program) []Instruction {
	sequence := g.skbCall(p)
	footer, _ := InstructionSequence(
		LdDW(RegR0, RegR10, g.mapFirstElementOffset),
		StDW(RegR0, g.magicNumber, 0),
		LdDW(RegR0, RegR10, g.mapPtrOffset),
		
		
	)
	temp, _ := LdMapElement(RegR0, 1, RegR10, -36)
	footer = append(footer, temp...)
	temp, _ = InstructionSequence(JmpNE(RegR0, 0, 1),
		Exit(),
		StDW(RegR0, g.magicNumber, 0),
		LdDW(RegR0, RegR10, g.mapPtrOffset),
	)
	footer = append(footer, temp...)
	temp, _ = LdMapElement(RegR0, 2, RegR10, -36)
	footer = append(footer, temp...)
	temp, _ = InstructionSequence(JmpNE(RegR0, 0, 1),
		Exit(),
		LdDW(RegR1, RegR10, g.skbReadOffset),
		StDW(RegR0, RegR1, 0),
		Mov64(RegR0, 0),
		Exit(),
	)
	footer = append(footer, temp...)
	
	sequence = append(sequence, footer...)
	return sequence
}
