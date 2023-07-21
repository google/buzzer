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

// AluImmInstruction represents an ALU operation with an immediate value
type AluImmInstruction struct {

	// Add all the basic things all instructions have.
	BaseInstruction

	// DstReg is where the result of the operation will be stored.
	DstReg *Register

	// Imm is the immediate value to use as src operand
	Imm int32
}

// GenerateBytecode generates the bytecode corresponding to this instruction.
func (c *AluImmInstruction) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeImmediateAluInstruction(c.Opcode, c.InstructionClass, c.DstReg.RegisterNumber(), c.Imm)}
	if c.nextInstruction != nil {
		bytecode = append(bytecode, c.nextInstruction.GenerateBytecode()...)
	}
	return bytecode
}

// GeneratePoc Generates the C macro that represents this instruction.
func (c *AluImmInstruction) GeneratePoc() []string {
	var insClass string
	if c.InstructionClass == InsClassAlu64 {
		insClass = "BPF_ALU64"
	} else {
		insClass = "BPF_ALU"
	}
	instrName := NameForAluInstruction(c.Opcode)
	regName := c.DstReg.ToString()
	macro := fmt.Sprintf("BPF_ALU_IMM(%s, /*dst=*/%s, /*imm=*/%d, /*ins_class=*/%s)", instrName, regName, c.Imm, insClass)
	r := []string{macro}
	if c.nextInstruction != nil {
		r = append(r, c.nextInstruction.GeneratePoc()...)
	}
	return r
}

// NewAluImmInstruction generates an operation structure that represents `op` with
// the given instruction category.
func NewAluImmInstruction(op, insClass uint8, dstReg *Register, imm int32) *AluImmInstruction {
	return &AluImmInstruction{
		BaseInstruction: BaseInstruction{Opcode: op, InstructionClass: insClass},
		DstReg:          dstReg,
		Imm:             imm,
	}
}

// Auxiliary functions that generate specific instructions.

// MovRegImm64 sets re to the specified value
func MovRegImm64(reg *Register, imm int32) *AluImmInstruction {
	return NewAluImmInstruction(AluMov, InsClassAlu64, reg, imm)
}

// AluRegInstruction Represents an ALU operation with register as src value.
type AluRegInstruction struct {

	// Add all the basic things all instructions have.
	BaseInstruction

	// DstReg is where the result will be stored.
	DstReg *Register

	// SrcReg is where to take the valuo for the second operand.
	SrcReg *Register
}

// GenerateBytecode generates the bytecode corresponding to this instruction.
func (c *AluRegInstruction) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeRegisterAluInstruction(c.Opcode, c.InstructionClass, c.DstReg.RegisterNumber(), c.SrcReg.RegisterNumber())}
	if c.nextInstruction != nil {
		bytecode = append(bytecode, c.nextInstruction.GenerateBytecode()...)
	}
	return bytecode
}

// GeneratePoc Generates the C macro that represents this instruction.
func (c *AluRegInstruction) GeneratePoc() []string {
	var insClass string
	if c.InstructionClass == InsClassAlu64 {
		insClass = "BPF_ALU64"
	} else {
		insClass = "BPF_ALU"
	}
	instrName := NameForAluInstruction(c.Opcode)
	dstRegName := c.DstReg.ToString()
	srcRegName := c.SrcReg.ToString()
	macro := fmt.Sprintf("BPF_ALU_REG(%s, /*dst=*/%s, /*src=*/%s, /*ins_class=*/%s)", instrName, dstRegName, srcRegName, insClass)
	r := []string{macro}
	if c.nextInstruction != nil {
		r = append(r, c.nextInstruction.GeneratePoc()...)
	}
	return r
}

// NewAluRegInstruction generates an operation structure that represents `op` with
// the given instruction category.
func NewAluRegInstruction(op, insClass uint8, dstReg *Register, srcReg *Register) *AluRegInstruction {
	return &AluRegInstruction{
		BaseInstruction: BaseInstruction{Opcode: op, InstructionClass: insClass},
		DstReg:          dstReg,
		SrcReg:          srcReg,
	}
}

// MovRegSrc64 Represents MOV operation where the src comes from a register.
func MovRegSrc64(srcReg, dstReg *Register) *AluRegInstruction {
	return NewAluRegInstruction(AluMov, InsClassAlu64, dstReg, srcReg)
}
