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

// GenerateRandomAluInstruction provides a random ALU operation with either
// IMM or Reg src that will be applied to a random dst reg.
func GenerateRandomAluInstruction(prog *Program) Instruction {
	op := uint8(prog.GetRNG().RandRange(0x00, 0x0c)) << 4

	var dstReg uint8
	if op == AluMov {
		dstReg = uint8(prog.GetRNG().RandRange(uint64(prog.MinRegister), uint64(prog.MaxRegister)))
	} else {
		dstReg = prog.GetRandomRegister()
	}
	dReg, _ := GetRegisterFromNumber(dstReg)

	var insClass uint8
	if prog.GetRNG().RandRange(0, 1) == 0 {
		insClass = InsClassAlu
	} else {
		insClass = InsClassAlu64
	}

	// Toss another coin to decide if we are going to do an imm alu
	// operation or one that uses a src register.
	var instr Instruction
	if prog.GetRNG().RandRange(0, 1) == 0 {
		instr = generateImmAluInstruction(op, insClass, dReg, prog)
	} else {
		instr = generateRegAluInstruction(op, insClass, dReg, prog)
	}

	return instr
}

// RandomJumpOp generates a random jump operator.
func RandomJumpOp(a *Program) uint8 {
	// https://docs.kernel.org/bpf/instruction-set.html#jump-instructions
	return uint8(a.GetRNG().RandRange(0x00, 0x0d))
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
		op = RandomJumpOp(prog)
		// Shift by 4 bits because we need to respect the ebpf encoding:
		// https://docs.kernel.org/bpf/instruction-set.html#id6
		op <<= 4
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
	value := int32(prog.GetRNG().RandRange(0, 0xFFFFFFFF))
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
		op = uint8(prog.GetRNG().RandRange(0x00, 0x0c)) << 4
	}

	if op == AluMov && !prog.IsRegisterInitialized(dstReg.RegisterNumber()) {
		prog.MarkRegisterInitialized(dstReg.RegisterNumber())
	}

	return NewAluRegInstruction(op, insClass, dstReg, srcReg)
}

// InstructionSequence abstracts away the process of creating a sequence of
// ebpf instructions. This should make writing ebpf programs in buzzer
// more readable and easier to achieve.
func InstructionSequence(instructions ...Instruction) (Instruction, error) {
	return instructionSequenceImpl(instructions)
}

// In order to deal with things like nested jumps, the instruction sequence
// feature needs to be a recursive function, hide the actual implementation
// from users using a non exported function.
func instructionSequenceImpl(instructions []Instruction) (Instruction, error) {
	if len(instructions) == 0 {
		// no more instructions to process, break the recursion.
		return nil, nil
	}
	var root, ptr Instruction
	advancePointer := func(i Instruction) {
		if root == nil {
			root = i
			ptr = root
		} else {
			ptr.SetNextInstruction(i)
			ptr = i
		}
	}

	for i := 0; i < len(instructions); i++ {
		instruction := instructions[i]

		if jmpInstr, ok := instruction.(*JmpImmInstruction); ok {
			if jmpInstr.FalseBranchSize == 0 && jmpInstr.Opcode != JmpExit {
				return nil, fmt.Errorf("Only Exit() and Jmp() can have an offset of 0")
			}
			falseBranchNextInstr, trueBranchNextInstr, err := handleJmpInstruction(instructions[i:], jmpInstr.FalseBranchSize)
			if err != nil {
				return nil, err
			}

			jmpInstr.FalseBranchNextInstr = falseBranchNextInstr
			jmpInstr.TrueBranchNextInstr = trueBranchNextInstr

			advancePointer(jmpInstr)

			// Break here because handleJmpInstruction should have processed the rest of the ebpf program.
			break
		} else if jmpInstr, ok := instruction.(*JmpRegInstruction); ok {
			if jmpInstr.FalseBranchSize == 0 {
				return nil, fmt.Errorf("JmpReg instruction cannot have jump offset of 0")
			}
			falseBranchNextInstr, trueBranchNextInstr, err := handleJmpInstruction(instructions[i:], jmpInstr.FalseBranchSize)
			if err != nil {
				return nil, err
			}
			jmpInstr.FalseBranchNextInstr = falseBranchNextInstr
			jmpInstr.TrueBranchNextInstr = trueBranchNextInstr

			advancePointer(jmpInstr)
			break
		} else {
			advancePointer(instruction)
		}
	}
	return root, nil
}

func handleJmpInstruction(instructions []Instruction, offset int16) (Instruction, Instruction, error) {
	if len(instructions) == 0 {
		// TODO: here and below, to improve testing lets define the possible
		// errors in a list somewhere else so we can compare directly that we
		// got the error we expect.
		return nil, nil, fmt.Errorf("handleJmpInstruction invocation should receive at least 1 instruction")
	}
	trueBranchStartIndex := int(offset) + 1
	if trueBranchStartIndex > len(instructions) {
		// TODO: For this error message and others, it would make debugging
		// easier if we could put the offending instruction.
		// For that we would need a way to convert an instruction to a
		// readable string, this is easy to do but let's do it in a follow
		// up patch.
		return nil, nil, fmt.Errorf("Jmp goes out of bounds")
	}

	// instructions[0] should be the jump itself.
	falseBranchInstrs := instructions[1:trueBranchStartIndex]
	trueBranchInstrs := instructions[trueBranchStartIndex:]

	falseBranchNextInstr, err := instructionSequenceImpl(falseBranchInstrs)
	if err != nil {
		return nil, nil, err
	}
	trueBranchNextInstr, err := instructionSequenceImpl(trueBranchInstrs)
	if err != nil {
		return nil, nil, err
	}
	return falseBranchNextInstr, trueBranchNextInstr, nil
}

// This function is meant to be used by all the Instruction Helper functions,
// to test if the supplied src parameter is of type int. Callers of the helper
// functions might provide an int, int64, int32, int16, int8, int as src
// parameter and it makes sense to centralize the logic to check for a data
// type here.
//
// If the passed data is indeed of an int data type, bool is true and
// the value casted to int() is returned.
//
// If it is not, it returns false and an arbitrary int()
func isIntType(src interface{}) (bool, int) {
	if srcInt, ok := src.(int); ok {
		return true, srcInt
	} else if srcInt64, ok := src.(int64); ok {
		return true, int(srcInt64)
	} else if srcInt32, ok := src.(int32); ok {
		return true, int(srcInt32)
	} else if srcInt16, ok := src.(int16); ok {
		return true, int(srcInt16)
	} else if srcInt8, ok := src.(int8); ok {
		return true, int(srcInt8)
	}

	return false, int(0)
}
