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

// AluImmOperation represents an ALU operation with an immediate value
type AluImmOperation struct {
	// Operation that this instruction represents.
	Operation uint8

	// InsClass is the instruction class.
	InsClass uint8

	// DstReg is where the result of the operation will be stored.
	DstReg *Register

	// Imm is the immediate value to use as src operand
	Imm               int32
	instructionNumber uint32
	nextInstruction   Operation
}

// GenerateBytecode generates the bytecode corresponding to this instruction.
func (c *AluImmOperation) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeImmediateAluOperation(c.Operation, c.InsClass, c.DstReg.RegisterNumber(), c.Imm)}
	if c.nextInstruction != nil {
		bytecode = append(bytecode, c.nextInstruction.GenerateBytecode()...)
	}
	return bytecode
}

// GenerateNextInstruction generates the next instruction.
func (c *AluImmOperation) GenerateNextInstruction(ast *Program) {
	if c.nextInstruction != nil {
		c.nextInstruction.GenerateNextInstruction(ast)
	} else {
		c.nextInstruction = ast.Gen.GenerateNextInstruction(ast)
	}
}

// NumerateInstruction sets the current instruction number.
func (c *AluImmOperation) NumerateInstruction(instrNo uint32) int {
	c.instructionNumber = instrNo
	instrNo++
	if c.nextInstruction != nil {
		return 1 + c.nextInstruction.NumerateInstruction(instrNo)
	}
	return 1
}

// SetNextInstruction manually sets the next instruction.
func (c *AluImmOperation) SetNextInstruction(next Operation) {
	if c.nextInstruction != nil {
		c.nextInstruction.SetNextInstruction(next)
	} else {
		c.nextInstruction = next
	}
}

// GeneratePoc Generates the C macro that represents this instruction.
func (c *AluImmOperation) GeneratePoc() []string {
	var insClass string
	if c.InsClass == InsClassAlu64 {
		insClass = "BPF_ALU64"
	} else {
		insClass = "BPF_ALU"
	}
	instrName := NameForAluInstruction(c.Operation)
	regName := c.DstReg.ToString()
	macro := fmt.Sprintf("BPF_ALU_IMM(%s, /*dst=*/%s, /*imm=*/%d, /*ins_class=*/%s)", instrName, regName, c.Imm, insClass)
	r := []string{macro}
	if c.nextInstruction != nil {
		r = append(r, c.nextInstruction.GeneratePoc()...)
	}
	return r
}

// NewAluImmOperation generates an operation structure that represents `op` with
// the given instruction category.
func NewAluImmOperation(op, insClass uint8, dstReg *Register, imm int32) *AluImmOperation {
	return &AluImmOperation{Operation: op, InsClass: insClass, DstReg: dstReg, Imm: imm}
}

// Auxiliary functions that generate specific instructions.

// MovRegImm64 sets re to the specified value
func MovRegImm64(reg *Register, imm int32) *AluImmOperation {
	return NewAluImmOperation(AluMov, InsClassAlu64, reg, imm)
}

// AluRegOperation Represents an ALU operation with register as src value.
type AluRegOperation struct {
	// Operation that this instruction represents.
	Operation uint8

	// InsClass instruction class of this operation.
	InsClass uint8

	// DstReg is where the result will be stored.
	DstReg *Register

	// SrcReg is where to take the valuo for the second operand.
	SrcReg *Register

	instructionNumber uint32
	nextInstruction   Operation
}

// GenerateBytecode generates the bytecode corresponding to this instruction.
func (c *AluRegOperation) GenerateBytecode() []uint64 {
	bytecode := []uint64{encodeRegisterAluOperation(c.Operation, c.InsClass, c.DstReg.RegisterNumber(), c.SrcReg.RegisterNumber())}
	if c.nextInstruction != nil {
		bytecode = append(bytecode, c.nextInstruction.GenerateBytecode()...)
	}
	return bytecode
}

// GenerateNextInstruction generates the next instruction.
func (c *AluRegOperation) GenerateNextInstruction(ast *Program) {
	if c.nextInstruction != nil {
		c.nextInstruction.GenerateNextInstruction(ast)
	} else {
		c.nextInstruction = ast.Gen.GenerateNextInstruction(ast)
	}
}

// NumerateInstruction sets the current instruction number.
func (c *AluRegOperation) NumerateInstruction(instrNo uint32) int {
	c.instructionNumber = instrNo
	instrNo++
	if c.nextInstruction != nil {
		return 1 + c.nextInstruction.NumerateInstruction(instrNo)
	}
	return 1
}

// SetNextInstruction manually sets the next instruction.
func (c *AluRegOperation) SetNextInstruction(next Operation) {
	if c.nextInstruction != nil {
		c.nextInstruction.SetNextInstruction(next)
	} else {
		c.nextInstruction = next
	}
}

// GeneratePoc Generates the C macro that represents this instruction.
func (c *AluRegOperation) GeneratePoc() []string {
	var insClass string
	if c.InsClass == InsClassAlu64 {
		insClass = "BPF_ALU64"
	} else {
		insClass = "BPF_ALU"
	}
	instrName := NameForAluInstruction(c.Operation)
	dstRegName := c.DstReg.ToString()
	srcRegName := c.SrcReg.ToString()
	macro := fmt.Sprintf("BPF_ALU_REG(%s, /*dst=*/%s, /*src=*/%s, /*ins_class=*/%s)", instrName, dstRegName, srcRegName, insClass)
	r := []string{macro}
	if c.nextInstruction != nil {
		r = append(r, c.nextInstruction.GeneratePoc()...)
	}
	return r
}

// NewAluRegOperation generates an operation structure that represents `op` with
// the given instruction category.
func NewAluRegOperation(op, insClass uint8, dstReg *Register, srcReg *Register) *AluRegOperation {
	return &AluRegOperation{Operation: op, InsClass: insClass, DstReg: dstReg, SrcReg: srcReg}
}

// MovRegSrc64 Represents MOV operation where the src comes from a register.
func MovRegSrc64(srcReg, dstReg *Register) *AluRegOperation {
	return NewAluRegOperation(AluMov, InsClassAlu64, dstReg, srcReg)
}
