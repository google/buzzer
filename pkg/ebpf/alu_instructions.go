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

	// Imm is the immediate value to use as src operand
	Imm int32
}

// GenerateBytecode generates the bytecode corresponding to this instruction.
func (c *AluImmInstruction) GenerateBytecode() []uint64 {
	return []uint64{encodeImmediateAluInstruction(c.Opcode, c.InstructionClass, c.DstReg.RegisterNumber(), c.Imm)}
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
	return r
}

// NewAluImmInstruction generates an operation structure that represents `op` with
// the given instruction category.
func NewAluImmInstruction(op, insClass uint8, dstReg *Register, imm int32) *AluImmInstruction {
	return &AluImmInstruction{
		BaseInstruction: BaseInstruction{Opcode: op, InstructionClass: insClass,
		DstReg:          dstReg},
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

	// SrcReg is where to take the valuo for the second operand.
	SrcReg *Register
}

// GenerateBytecode generates the bytecode corresponding to this instruction.
func (c *AluRegInstruction) GenerateBytecode() []uint64 {
	return []uint64{encodeRegisterAluInstruction(c.Opcode, c.InstructionClass, c.DstReg.RegisterNumber(), c.SrcReg.RegisterNumber())}
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
	return r
}

// NewAluRegInstruction generates an operation structure that represents `op` with
// the given instruction category.
func NewAluRegInstruction(op, insClass uint8, dstReg *Register, srcReg *Register) *AluRegInstruction {
	return &AluRegInstruction{
		BaseInstruction: BaseInstruction{Opcode: op, 

		InstructionClass: insClass,
		DstReg:          dstReg},
		SrcReg:          srcReg,
	}
}

func newAluInstruction(opcode, insclass uint8, dstReg *Register, src interface{}) Instruction {
	isInt, srcInt := isIntType(src)
	if isInt {
		return NewAluImmInstruction(opcode, insclass, dstReg, int32(srcInt))
	} else if srcReg, ok := src.(*Register); ok {
		return NewAluRegInstruction(opcode, insclass, dstReg, srcReg)
	}
	return nil
}

// Add64 Creates a new 64 bit Add instruction that is either imm or reg depending
// on the data type of src
func Add64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluAdd, InsClassAlu64, dstReg, src)
}

// Add Creates a new 32 bit Add instruction that is either imm or reg depending
// on the data type of src
func Add(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluAdd, InsClassAlu, dstReg, src)
}

// Sub64 Creates a new 64 bit Sub instruction that is either imm or reg depending
// on the data type of src
func Sub64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluSub, InsClassAlu64, dstReg, src)
}

// Sub Creates a new 32 bit Sub instruction that is either imm or reg depending
// on the data type of src
func Sub(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluSub, InsClassAlu, dstReg, src)
}

// Mul64 Creates a new 64 bit Mul instruction that is either imm or reg depending
// on the data type of src
func Mul64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluMul, InsClassAlu64, dstReg, src)
}

// Mul Creates a new 32 bit Mul instruction that is either imm or reg depending
// on the data type of src
func Mul(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluMul, InsClassAlu, dstReg, src)
}

// Div64 Creates a new 64 bit Div instruction that is either imm or reg depending
// on the data type of src
func Div64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluDiv, InsClassAlu64, dstReg, src)
}

// Div Creates a new 32 bit Div instruction that is either imm or reg depending
// on the data type of src
func Div(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluDiv, InsClassAlu, dstReg, src)
}

// Or64 Creates a new 64 bit Or instruction that is either imm or reg depending
// on the data type of src
func Or64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluOr, InsClassAlu64, dstReg, src)
}

// Or Creates a new 32 bit Or instruction that is either imm or reg depending
// on the data type of src
func Or(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluOr, InsClassAlu, dstReg, src)
}

// And64 Creates a new 64 bit And instruction that is either imm or reg depending
// on the data type of src
func And64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluAnd, InsClassAlu64, dstReg, src)
}

// And Creates a new 32 bit And instruction that is either imm or reg depending
// on the data type of src
func And(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluAnd, InsClassAlu, dstReg, src)
}

// Lsh64 Creates a new 64 bit Lsh instruction that is either imm or reg depending
// on the data type of src
func Lsh64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluLsh, InsClassAlu64, dstReg, src)
}

// Lsh Creates a new 32 bit Lsh instruction that is either imm or reg depending
// on the data type of src
func Lsh(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluLsh, InsClassAlu, dstReg, src)
}

// Rsh64 Creates a new 64 bit Rsh instruction that is either imm or reg depending
// on the data type of src
func Rsh64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluRsh, InsClassAlu64, dstReg, src)
}

// Rsh Creates a new 32 bit Rsh instruction that is either imm or reg depending
// on the data type of src
func Rsh(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluRsh, InsClassAlu, dstReg, src)
}

// Neg64 Creates a new 64 bit Neg instruction that is either imm or reg depending
// on the data type of src
func Neg64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluNeg, InsClassAlu64, dstReg, src)
}

// Neg Creates a new 32 bit Neg instruction that is either imm or reg depending
// on the data type of src
func Neg(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluNeg, InsClassAlu, dstReg, src)
}

// Mod64 Creates a new 64 bit Mod instruction that is either imm or reg depending
// on the data type of src
func Mod64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluMod, InsClassAlu64, dstReg, src)
}

// Mod Creates a new 32 bit Mod instruction that is either imm or reg depending
// on the data type of src
func Mod(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluMod, InsClassAlu, dstReg, src)
}

// Xor64 Creates a new 64 bit Xor instruction that is either imm or reg depending
// on the data type of src
func Xor64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluXor, InsClassAlu64, dstReg, src)
}

// Xor Creates a new 32 bit Xor instruction that is either imm or reg depending
// on the data type of src
func Xor(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluXor, InsClassAlu, dstReg, src)
}

// Mov64 Creates a new 64 bit Mov instruction that is either imm or reg depending
// on the data type of src
func Mov64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluMov, InsClassAlu64, dstReg, src)
}

// Mov Creates a new 32 bit Mov instruction that is either imm or reg depending
// on the data type of src
func Mov(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluMov, InsClassAlu, dstReg, src)
}

// Arsh64 Creates a new 64 bit Arsh instruction that is either imm or reg depending
// on the data type of src
func Arsh64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluArsh, InsClassAlu64, dstReg, src)
}

// Arsh Creates a new 32 bit Arsh instruction that is either imm or reg depending
// on the data type of src
func Arsh(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluArsh, InsClassAlu, dstReg, src)
}

// End64 Creates a new 64 bit End instruction that is either imm or reg depending
// on the data type of src
func End64(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluEnd, InsClassAlu64, dstReg, src)
}

// End Creates a new 32 bit End instruction that is either imm or reg depending
// on the data type of src
func End(dstReg *Register, src interface{}) Instruction {
	return newAluInstruction(AluEnd, InsClassAlu, dstReg, src)
}
