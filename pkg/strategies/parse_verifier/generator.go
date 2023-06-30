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

	"buzzer/pkg/ebpf/ebpf"
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

func (g *Generator) generateHeader(prog *ebpf.Program) ebpf.Operation {
	var root, ptr ebpf.Operation
	root = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeDW,
		Mode:     ebpf.StLdModeIMM,
		InsClass: ebpf.InsClassLd,
		DstReg:   ebpf.RegR6,
		SrcReg:   ebpf.PseudoMapFD,
		Imm:      int32(prog.LogMap()),
	}
	prog.MarkRegisterInitialized(ebpf.RegR6.RegisterNumber())
	ptr = root
	// Initializing R6 to a pointer value via a 8-byte immediate
	// generates a wide instruction. So, two 8-byte values.
	hSize := int32(2)

	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := ebpf.GetRegisterFromNumber(uint8(i))
		regVal := int32(prog.GetRNG().RandInt())
		nextInstr := ebpf.MovRegImm64(reg, regVal)
		ptr.SetNextInstruction(nextInstr)
		ptr = nextInstr
		prog.MarkRegisterInitialized(reg.RegisterNumber())
		hSize++
	}
	g.headerSize = hSize
	return root
}

// GenerateNextInstruction is responsible for recursively building the ebpf program tree
func (g *Generator) GenerateNextInstruction(prog *ebpf.Program) ebpf.Operation {
	// We reached the number of instructions we were told to generate.
	if g.instructionCount == 0 {
		return g.generateProgramFooter(prog)
	}
	g.instructionCount--

	instr := ebpf.GenerateRandomAluOperation(prog)

	var dstReg *ebpf.Register

	if alui, ok := instr.(*ebpf.AluImmOperation); ok {
		dstReg = alui.DstReg
	} else if alui, ok := instr.(*ebpf.AluRegOperation); ok {
		dstReg = alui.DstReg
	} else {
		fmt.Printf("Could not get dst reg for operation %v", instr)
		return nil
	}

	stInst, _ := g.generateStateStoringSnippet(dstReg, prog)
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

func (g *Generator) generateProgramFooter(prog *ebpf.Program) ebpf.Operation {
	reg0 := ebpf.MovRegImm64(ebpf.RegR0, 0)
	reg0.SetNextInstruction(ebpf.ExitOperation())
	return reg0
}

// Generate is the main function that builds the ebpf for this strategy.
func (g *Generator) Generate(prog *ebpf.Program) ebpf.Operation {
	root := g.generateHeader(prog)
	root.SetNextInstruction(g.GenerateNextInstruction(prog))
	return root
}

func (g *Generator) generateStateStoringSnippet(dstReg *ebpf.Register, prog *ebpf.Program) (ebpf.Operation, ebpf.Operation) {
	var instr, next, ptr ebpf.Operation

	// The storing snippet looks something like this:
	// - r0 = ebpf.logCount
	// - *(r10 - 4) = r0; Where R10 is the stack pointer, we store the value
	// of ebpf.logCount into the stack so we can write it into the map.
	// - r1 = r6; where r6 contains the map file descriptor
	// - r2 = r10
	// - r2 -= 4; We make r2 point to the ebpf.count value we stored.
	// - r0 = bpf_map_lookup_element(map_fd, element_index)
	// - if r0 == null exit(); We need to check for null pointers.
	// - *(r0) = rX; where rX is the register that was the destination of
	//   the random operation.
	instr = ebpf.MovRegImm64(ebpf.RegR0, g.logCount)
	ptr = instr

	offset := int16(-4)

	next = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeW,
		Mode:     ebpf.StLdModeMEM,
		InsClass: ebpf.InsClassStx,
		DstReg:   ebpf.RegR10,
		SrcReg:   ebpf.RegR0,
		Offset:   offset,
		Imm:      ebpf.UnusedField,
	}
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegSrc64(ebpf.RegR6, ebpf.RegR1)
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegSrc64(ebpf.RegR10, ebpf.RegR2)
	ptr.SetNextInstruction(next)
	ptr = next

	subs := int32(-4)

	next = ebpf.NewAluImmOperation(ebpf.AluAdd, ebpf.InsClassAlu64, ebpf.RegR2, subs)
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.CallFunction(ebpf.MapLookup)
	ptr.SetNextInstruction(next)
	ptr = next

	guard := ebpf.GuardJump(ebpf.JmpJNE, ebpf.InsClassJmp, ebpf.RegR0, 0)
	ptr.SetNextInstruction(guard)

	next = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeDW,
		Mode:     ebpf.StLdModeMEM,
		InsClass: ebpf.InsClassStx,
		DstReg:   ebpf.RegR0,
		SrcReg:   dstReg,
		Offset:   ebpf.UnusedField,
		Imm:      ebpf.UnusedField,
	}
	guard.FalseBranchNextInstr = ebpf.ExitOperation()
	guard.FalseBranchSize = 1
	guard.TrueBranchNextInstr = next
	ptr = next

	return instr, ptr
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
