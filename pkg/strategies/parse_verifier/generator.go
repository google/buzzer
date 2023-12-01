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

package parseverifier

import (
	"fmt"

	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/rand"
)

// Generator is responsible for constructing the ebpf for this strategy.
type Generator struct {
	instructionCount int

	// The number of instructions generated excluding instrumentation instructions.
	logCount int32

	headerSize int32

	// A map from the generated instruction number to the assembled instruction offset.
	offsetMap map[int32]int32

	// A map from generated instruction number to the size (in bytes) of the
	// generated code including instrumentation instructions.
	sizeMap map[int32]int32

	// A map from the generated instruction number to the destination register
	// of the instruction.
	regMap map[int32]uint8
}

func (g *Generator) generateHeader(prog *Program) Instruction {
	var root, ptr Instruction
	root = &MemoryInstruction{
		BaseInstruction: BaseInstruction{
			InstructionClass: InsClassLd,
		},
		Size:   StLdSizeDW,
		Mode:   StLdModeIMM,
		DstReg: RegR6,
		SrcReg: PseudoMapFD,
		Imm:    int32(prog.LogMap()),
	}
	prog.MarkRegisterInitialized(RegR6.RegisterNumber())
	ptr = root
	// Initializing R6 to a pointer value via a 8-byte immediate
	// generates a wide instruction. So, two 8-byte values.
	hSize := int32(2)

	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := GetRegisterFromNumber(uint8(i))
		regVal := int32(rand.SharedRNG.RandInt())
		nextInstr := MovRegImm64(reg, regVal)
		ptr.SetNextInstruction(nextInstr)
		ptr = nextInstr
		prog.MarkRegisterInitialized(reg.RegisterNumber())
		hSize++
	}
	g.headerSize = hSize
	return root
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree
func (g *Generator) GenerateNextInstruction(prog *Program) Instruction {
	// We reached the number of instructions we were told to generate.
	if g.instructionCount == 0 {
		return g.generateProgramFooter(prog)
	}
	g.instructionCount--

	instr := GenerateRandomAluInstruction(prog)

	var dstReg *Register

	if alui, ok := instr.(*AluImmInstruction); ok {
		dstReg = alui.DstReg
	} else if alui, ok := instr.(*AluRegInstruction); ok {
		dstReg = alui.DstReg
	} else {
		fmt.Printf("Could not get dst reg for operation %v", instr)
		return nil
	}

	stInst := g.generateStateStoringSnippet(dstReg, prog)
	instr.SetNextInstruction(stInst)
	instrLen := int32(len(instr.GenerateBytecode()))
	instrOffset := int32(0)
	if g.logCount == 0 {
		instrOffset = g.headerSize
	} else {
		instrOffset = g.offsetMap[g.logCount-1] + g.sizeMap[g.logCount-1]
	}

	g.offsetMap[g.logCount] = instrOffset
	g.regMap[g.logCount] = dstReg.RegisterNumber()
	g.sizeMap[g.logCount] = instrLen
	g.logCount++

	instr.GenerateNextInstruction(prog)
	return instr
}

func (g *Generator) generateProgramFooter(prog *Program) Instruction {
	reg0 := MovRegImm64(RegR0, 0)
	reg0.SetNextInstruction(Exit())
	return reg0
}

// Generate is the main function that builds the ebpf for this strategy.
func (g *Generator) Generate(prog *Program) Instruction {
	root := g.generateHeader(prog)
	root.SetNextInstruction(g.GenerateNextInstruction(prog))
	return root
}

func (g *Generator) generateStateStoringSnippet(dstReg *Register, prog *Program) Instruction {
	// The storing snippet looks something like this:
	// - r0 = logCount
	// - *(r10 - 4) = r0; Where R10 is the stack pointer, we store the value
	// of logCount into the stack so we can write it into the map.
	// - r1 = r6; where r6 contains the map file descriptor
	// - r2 = r10
	// - r2 -= 4; We make r2 point to the count value we stored.
	// - r0 = bpf_map_lookup_element(map_fd, element_index)
	// - if r0 == null exit(); We need to check for null pointers.
	// - *(r0) = rX; where rX is the register that was the destination of
	//   the random operation.
	root, _ := InstructionSequence(
		Mov64(RegR0, g.logCount),
		StW(RegR10, RegR0, -4),
		Mov64(RegR1, RegR6),
		Mov64(RegR2, RegR10),
		Add64(RegR2, -4),
		Call(MapLookup),
		JmpNE(RegR0, 0, 1),
		Exit(),
		StDW(RegR0, dstReg, 0),
	)

	return root
}

// GetProgramOffset returns the program offset corresponding to the n'th
// randomly generated instruction.
func (g *Generator) GetProgramOffset(n int32) int32 {
	return g.offsetMap[n]
}

// GetDestReg returns the destination registers of the n'th randomly
// generated instruction.
func (g *Generator) GetDestReg(n int32) uint8 {
	return g.regMap[n]
}
