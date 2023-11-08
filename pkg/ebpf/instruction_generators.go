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
	"buzzer/pkg/rand"
)

// The generators below take as parameter the program to generate instructions
// into, this is so they can make sure the instructions generated use initialized
// registers only. Therefore these instructions are more "safe" to use.

// GenerateRandomAluInstruction provides a random ALU operation with either
// IMM or Reg src that will be applied to a random dst reg.
func GenerateRandomAluInstruction(prog *Program) Instruction {
	op := RandomAluOp() 

	var dstReg uint8
	if op == AluMov {
		dstReg = uint8(rand.SharedRNG.RandRange(uint64(prog.MinRegister), uint64(prog.MaxRegister)))
	} else {
		dstReg = prog.GetRandomRegister()
	}
	dReg, _ := GetRegisterFromNumber(dstReg)

	var insClass uint8
	if rand.SharedRNG.RandRange(0, 1) == 0 {
		insClass = InsClassAlu
	} else {
		insClass = InsClassAlu64
	}

	// Toss another coin to decide if we are going to do an imm alu
	// operation or one that uses a src register.
	var instr Instruction
	if rand.SharedRNG.RandRange(0, 1) == 0 {
		instr = generateImmAluInstruction(op, insClass, dReg, prog)
	} else {
		instr = generateRegAluInstruction(op, insClass, dReg, prog)
	}

	return instr
}

// RandomJumpOp generates a random jump operator.
func RandomJumpOp() uint8 {
	// https://docs.kernel.org/bpf/instruction-set.html#jump-instructions
	return uint8(rand.SharedRNG.RandRange(0x00, 0x0d)) << 4
}

func RandomAluOp() uint8 {
	// Shift by 4 bits because we need to respect the ebpf encoding:
	// https://docs.kernel.org/bpf/instruction-set.html#id6
	return uint8(rand.SharedRNG.RandRange(0x00, 0x0c)) << 4
}

// IsConditional determines if the operator is not an Exit, Call or JA
// operation.
func IsConditional(op uint8) bool {
	return !(op == JmpExit || op == JmpCALL || op == JmpJA)
}

// GenerateRandomJmpRegInstruction generates a random jump operation where
// the src operand is a random register. The generator functions tell the
// instruction how to generate the true/false branches.
func GenerateRandomJmpRegInstruction(prog *Program, trueBranchGenerator func(prog *Program) Instruction, falseBranchGenerator func(prog *Program) (Instruction, int16)) Instruction {
	var op uint8
	for {
		op = RandomJumpOp()
		if IsConditional(op) {
			break
		}
	}

	dstReg, _ := GetRegisterFromNumber(prog.GetRandomRegister())
	srcReg, _ := GetRegisterFromNumber(prog.GetRandomRegister())
	for srcReg == dstReg {
		srcReg, _ = GetRegisterFromNumber(prog.GetRandomRegister())
	}

	return &JmpRegInstruction{
		BaseInstruction: BaseInstruction{
			Opcode:           op,
			InstructionClass: InsClassJmp,
		},
		BaseJmpInstruction: BaseJmpInstruction{
			DstReg:               dstReg,
			trueBranchGenerator:  trueBranchGenerator,
			falseBranchGenerator: falseBranchGenerator,
		},
		SrcReg: srcReg,
	}

}

func generateImmAluInstruction(op, insClass uint8, dstReg *Register, prog *Program) Instruction {
	value := int32(rand.SharedRNG.RandRange(0, 0xFFFFFFFF))
	switch op {
	case AluRsh, AluLsh, AluArsh:
		var maxShift = int32(64)
		if insClass == InsClassAlu {
			maxShift = 32
		}
		value = value % maxShift
		if value < 0 {
			value *= -1
		}
	case AluNeg:
		value = 0
	case AluMov:
		if !prog.IsRegisterInitialized(dstReg.RegisterNumber()) {
			prog.MarkRegisterInitialized(dstReg.RegisterNumber())
		}
	}

	return NewAluImmInstruction(op, insClass, dstReg, value)
}

func generateRegAluInstruction(op, insClass uint8, dstReg *Register, prog *Program) Instruction {
	srcReg, _ := GetRegisterFromNumber(prog.GetRandomRegister())
	// Negation is not supported with Register as src.
	for op == AluNeg {
		op = uint8(rand.SharedRNG.RandRange(0x00, 0x0c)) << 4
	}

	if op == AluMov && !prog.IsRegisterInitialized(dstReg.RegisterNumber()) {
		prog.MarkRegisterInitialized(dstReg.RegisterNumber())
	}

	return NewAluRegInstruction(op, insClass, dstReg, srcReg)
}

// The generators below are more flexible to use but also provide less
// guarantees on if the instruction will pass the verifier (e.g registers
// might not be initialized yet)
func RandomAluInstruction() Instruction {
	op := RandomAluOp()

	var insClass uint8
	if rand.SharedRNG.OneOf(2) {
		insClass = InsClassAlu64
	} else {
		insClass = InsClassAlu
	}

	dstReg := RandomRegister()

	var src any

	if rand.SharedRNG.OneOf(2) {
		src = uint32(rand.SharedRNG.RandRange(0, 0xffffffff))
	} else {
		src = RandomRegister()
	}

	return newAluInstruction(op, insClass, dstReg, src)
}

// RandomJmpInstruction generates a random jmp instruction that has an
// offset of at most `maxOffset` this is to minimize the possibility of a jmp
// out of the bounds of a program.
func RandomJmpInstruction(maxOffset uint64) Instruction {
	op := RandomJumpOp()

	var insClass uint8
	if rand.SharedRNG.OneOf(2) {
		insClass = InsClassJmp32
	} else {
		insClass = InsClassJmp
	}

	dstReg := RandomRegister()

	var src any

	if rand.SharedRNG.OneOf(2) {
		src = uint32(rand.SharedRNG.RandRange(0, 0xffffffff))
	} else {
		src = RandomRegister()
	}

	offset := int16(rand.SharedRNG.RandRange(1, maxOffset))
	return newJmpInstruction(op, insClass, dstReg, src, offset)
}
