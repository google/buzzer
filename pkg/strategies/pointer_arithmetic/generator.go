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
	"buzzer/pkg/ebpf/ebpf"
)

// Generator is responsible for constructing the ebpf for this strategy.
type Generator struct {
	instructionCount int
	magicNumber      int32
}

func (g *Generator) generateHeader(prog *ebpf.Program) ebpf.Operation {
	var root, ptr ebpf.Operation
	for i := prog.MinRegister; i <= prog.MaxRegister; i++ {
		reg, _ := ebpf.GetRegisterFromNumber(uint8(i))
		regVal := int32(prog.GetRNG().RandInt())
		nextInstr := ebpf.MovRegImm64(reg, regVal)
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
func (g *Generator) GenerateNextInstruction(prog *ebpf.Program) ebpf.Operation {
	// We reached the number of instructions we were told to generate.
	if g.instructionCount == 0 {
		return g.generateProgramFooter(prog)
	}
	g.instructionCount--

	var instr ebpf.Operation

	// Generate about 40% of instructions as jumps.
	if prog.GetRNG().RandRange(1, 100) <= 60 {
		instr = ebpf.GenerateRandomAluOperation(prog)
	} else {
		falseBranchGenerator := func(a *ebpf.Program) (ebpf.Operation, int16) {
			// 20 is an arbitrary number here.
			operationQuantity := int16(20)
			root := ebpf.GenerateRandomAluOperation(prog)
			ptr := root
			for i := int16(1); i < operationQuantity; i++ {
				next := ebpf.GenerateRandomAluOperation(prog)
				ptr.SetNextInstruction(next)
				ptr = next
			}
			return root, operationQuantity
		}
		instr = ebpf.GenerateRandomJmpRegOperation(prog, g.GenerateNextInstruction, falseBranchGenerator)
	}
	instr.GenerateNextInstruction(prog)
	return instr
}

func (g *Generator) generateProgramFooter(prog *ebpf.Program) ebpf.Operation {
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
	var root, ptr, next ebpf.Operation

	root = ebpf.MovRegImm64(ebpf.RegR0, 0)
	ptr = root

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

	// Load the map file descriptor to Register 4.
	next = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeDW,
		Mode:     ebpf.StLdModeIMM,
		InsClass: ebpf.InsClassLd,
		DstReg:   ebpf.RegR4,
		SrcReg:   ebpf.PseudoMapFD,
		Imm:      int32(prog.LogMap()),
	}
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegSrc64(ebpf.RegR4, ebpf.RegR1)
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegSrc64(ebpf.RegR10, ebpf.RegR2)
	ptr.SetNextInstruction(next)
	ptr = next

	subs := int32(-4)

	next = ebpf.NewAluImmOperation(ebpf.AluAdd, ebpf.InsClassAlu64, ebpf.RegR2, subs)
	ptr.SetNextInstruction(next)
	ptr = next

	// Load pointer to map element.
	next = ebpf.CallFunction(ebpf.MapLookup)
	ptr.SetNextInstruction(next)
	ptr = next

	guard := ebpf.GuardJump(ebpf.JmpJNE, ebpf.InsClassJmp, ebpf.RegR0, 0)
	guard.FalseBranchNextInstr = ebpf.ExitOperation()
	guard.FalseBranchSize = 1
	ptr.SetNextInstruction(guard)

	// Choose random register.
	chosenReg, _ := ebpf.GetRegisterFromNumber(prog.GetRandomRegister())

	// Perform pointer arithmetic with the chosen register.
	next = ebpf.NewAluRegOperation(ebpf.AluAdd, ebpf.InsClassAlu64, ebpf.RegR0, chosenReg)
	guard.TrueBranchNextInstr = next
	ptr = next

	next = ebpf.MovRegImm64(ebpf.RegR3, g.magicNumber)
	ptr.SetNextInstruction(next)
	ptr = next

	// Store the magic number, if we get here then the verifier thinks
	// the random register is 0.
	next = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeDW,
		Mode:     ebpf.StLdModeMEM,
		InsClass: ebpf.InsClassStx,
		DstReg:   ebpf.RegR0,
		SrcReg:   ebpf.RegR3,
		Offset:   ebpf.UnusedField,
		Imm:      ebpf.UnusedField,
	}
	ptr.SetNextInstruction(next)
	ptr = next

	// Repeat the above but no pointer arithmetic and we are writing
	// to the second map element.
	next = ebpf.MovRegImm64(ebpf.RegR0, 1)
	ptr.SetNextInstruction(next)
	ptr = next

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

	next = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeDW,
		Mode:     ebpf.StLdModeIMM,
		InsClass: ebpf.InsClassLd,
		DstReg:   ebpf.RegR4,
		SrcReg:   ebpf.PseudoMapFD,
		Imm:      int32(prog.LogMap()),
	}
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegSrc64(ebpf.RegR4, ebpf.RegR1)
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegSrc64(ebpf.RegR10, ebpf.RegR2)
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.NewAluImmOperation(ebpf.AluAdd, ebpf.InsClassAlu64, ebpf.RegR2, subs)
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.CallFunction(ebpf.MapLookup)
	ptr.SetNextInstruction(next)
	ptr = next

	guard = ebpf.GuardJump(ebpf.JmpJNE, ebpf.InsClassJmp, ebpf.RegR0, 0)
	guard.FalseBranchNextInstr = ebpf.ExitOperation()
	guard.FalseBranchSize = 1
	ptr.SetNextInstruction(guard)

	next = ebpf.MovRegImm64(ebpf.RegR3, g.magicNumber)
	guard.TrueBranchNextInstr = next
	ptr = next

	next = &ebpf.MemoryOperation{
		Size:     ebpf.StLdSizeDW,
		Mode:     ebpf.StLdModeMEM,
		InsClass: ebpf.InsClassStx,
		DstReg:   ebpf.RegR0,
		SrcReg:   ebpf.RegR3,
		Offset:   ebpf.UnusedField,
		Imm:      ebpf.UnusedField,
	}
	ptr.SetNextInstruction(next)
	ptr = next

	next = ebpf.MovRegImm64(ebpf.RegR0, 0)
	ptr.SetNextInstruction(next)
	ptr = next
	ptr.SetNextInstruction(ebpf.ExitOperation())

	return root
}

// Generate is the main function that builds the ebpf for this strategy.
func (g *Generator) Generate(prog *ebpf.Program) ebpf.Operation {
	root := g.generateHeader(prog)
	root.SetNextInstruction(g.GenerateNextInstruction(prog))
	return root
}
