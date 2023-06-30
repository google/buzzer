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
)

// MemoryOperation Represents an eBPF load/store operation with an immediate value.
type MemoryOperation struct {
	instructionNumber uint32

	// Size of the operation to make.
	Size uint8

	// Mode of the operation.
	Mode uint8

	// InsClass represents the instruction class.
	InsClass uint8

	// DstReg represents the destination register.
	DstReg *Register

	// Even if this is an imm operation, it seems that ebpf uses the
	// src register to point at what type of value we are loading from
	// memory. E.G. if srcReg is set to 0x1, the imm will get treated as
	// a map fd. (http://shortn/_cHoySHsuW2)

	// SrcReg is the source register.
	SrcReg *Register

	// Imm value to use.
	Imm int32

	// Offset of memory region to operate.
	Offset int16

	nextInstr Operation
}

// GenerateBytecode generates the bytecode associated with this instruction.
func (c *MemoryOperation) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeImmediateStOrLdOperation(c.InsClass, c.Size, c.Mode, c.DstReg.RegisterNumber(), c.SrcReg.RegisterNumber(), c.Imm, c.Offset)}

	// It seems that the ld_imm64 instructions need a "pseudo instruction"
	// after them, the documentation is not clear about it but
	// we can find references to insn[1] (which refers to it) in the
	// verifier code: http://shortn/_cHoySHsuW2
	if c.InsClass == InsClassLd && c.Mode == StLdModeIMM {
		bytecode = append(bytecode, uint64(0))
	}
	if c.nextInstr != nil {
		bytecode = append(bytecode, c.nextInstr.GenerateBytecode()...)
	}
	return bytecode
}

// GenerateNextInstruction uses the ast generator to generate the next instruction.
func (c *MemoryOperation) GenerateNextInstruction(ast *Program) {
	if c.nextInstr != nil {
		c.nextInstr.GenerateNextInstruction(ast)
	} else {
		c.nextInstr = ast.Gen.GenerateNextInstruction(ast)
	}
}

// SetNextInstruction sets the next instruction manually.
func (c *MemoryOperation) SetNextInstruction(next Operation) {
	if c.nextInstr != nil {
		c.nextInstr.SetNextInstruction(next)
	} else {
		c.nextInstr = next
	}
}

// GetNextInstruction returns the next instruction, mostly used for testing
// purposes.
func (c *MemoryOperation) GetNextInstruction() Operation {
	return c.nextInstr
}

func (c *MemoryOperation) setInstructionNumber(instrNo uint32) {
	c.instructionNumber = instrNo
}

// NumerateInstruction numerates the instruction.
func (c *MemoryOperation) NumerateInstruction(instrNo uint32) int {
	c.instructionNumber = instrNo
	instrNo++
	if c.nextInstr != nil {
		return 1 + c.nextInstr.NumerateInstruction(instrNo)
	}
	return 1
}

// GeneratePoc generates the C macros to repro this program.
func (c *MemoryOperation) GeneratePoc() []string {
	var macro string
	if c.InsClass == InsClassLd && c.Mode == StLdModeIMM {
		macro = fmt.Sprintf("BPF_LD_MAP_FD(/*dst=*/%d, map_fd)", c.DstReg)
	} else {
		var insClass string
		if c.InsClass == InsClassStx {
			insClass = "BPF_STX"
		} else {
			insClass = "BPF_LDX"
		}
		var size string
		switch c.Size {
		case StLdSizeW:
			size = "BPF_W"
		case StLdSizeH:
			size = "BPF_H"
		case StLdSizeB:
			size = "BPF_B"
		case StLdSizeDW:
			size = "BPF_DW"
		default:
			size = "unknown"
		}
		macro = fmt.Sprintf("BPF_MEM_OPERATION(%s, %s, /*dst=*/%d, /*src=*/%d, /*offset=*/%d)", insClass, size, c.DstReg, c.SrcReg, c.Offset)
	}

	r := []string{macro}
	if c.nextInstr != nil {
		r = append(r, c.nextInstr.GeneratePoc()...)
	}
	return r
}
