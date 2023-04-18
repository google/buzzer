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

// GenerateRandomAluOperation provides a random ALU operation with either
// IMM or Reg src that will be applied to a random dst reg.
func GenerateRandomAluOperation(prog *Program) Operation {
	op := uint8(prog.GetRNG().RandRange(0x00, 0x0c)) << 4

	var dstReg uint8
	if op == AluMov {
		dstReg = uint8(prog.GetRNG().RandRange(uint64(prog.MinRegister), uint64(prog.MaxRegister)))
	} else {
		dstReg = prog.GetRandomRegister()
	}

	var insClass uint8
	if prog.GetRNG().RandRange(0, 1) == 0 {
		insClass = InsClassAlu
	} else {
		insClass = InsClassAlu64
	}

	// Toss another coin to decide if we are going to do an imm alu
	// operation or one that uses a src register.
	var instr Operation
	if prog.GetRNG().RandRange(0, 1) == 0 {
		instr = generateImmAluOperation(op, insClass, dstReg, prog)
	} else {
		instr = generateRegAluOperation(op, insClass, dstReg, prog)
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

// GenerateRandomJmpRegOperation generates a random jump operation where
// the src operand is a random register. The generator functions tell the
// instruction how to generate the true/false branches.
func GenerateRandomJmpRegOperation(prog *Program, trueBranchGenerator func(prog *Program) Operation, falseBranchGenerator func(prog *Program) (Operation, int16)) Operation {

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

	dstReg := prog.GetRandomRegister()
	srcReg := prog.GetRandomRegister()
	for srcReg == dstReg {
		srcReg = prog.GetRandomRegister()
	}

	return &RegJMPOperation{
		Instruction:          op,
		InsClass:             InsClassJmp,
		DstReg:               dstReg,
		SrcReg:               srcReg,
		trueBranchGenerator:  trueBranchGenerator,
		falseBranchGenerator: falseBranchGenerator,
	}

}

func generateImmAluOperation(op, insClass, dstReg uint8, prog *Program) Operation {
	value := int32(prog.GetRNG().RandRange(0, 0xFFFFFFFF))
	switch op {
	case AluRsh, AluLsh, AluArsh:
		var maxShift = int32(64)
		if insClass == InsClassAlu {
			maxShift = 32
		}
		value = value % maxShift
	case AluNeg:
		value = 0
	case AluMov:
		if !prog.IsRegisterInitialized(dstReg) {
			prog.MarkRegisterInitialized(dstReg)
		}
	}

	return NewAluImmOperation(op, insClass, dstReg, value)
}

func generateRegAluOperation(op, insClass, dstReg uint8, prog *Program) Operation {
	srcReg := prog.GetRandomRegister()
	// Negation is not supported with Register as src.
	for op == AluNeg {
		op = uint8(prog.GetRNG().RandRange(0x00, 0x0c)) << 4
	}

	if op == AluMov && !prog.IsRegisterInitialized(dstReg) {
		prog.MarkRegisterInitialized(dstReg)
	}

	return NewAluRegOperation(op, insClass, dstReg, srcReg)
}
