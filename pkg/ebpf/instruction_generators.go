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
	pb "buzzer/proto/ebpf_go_proto"
)

// GenerateRandomAluInstruction provides a random ALU operation with either
// IMM or Reg src that will be applied to a random dst reg.
func RandomAluInstruction() *pb.Instruction {
	op := RandomAluOp()
	dstReg := RandomRegister()
	var insClass pb.InsClass
	if rand.SharedRNG.RandRange(0, 1) == 0 {
		insClass = pb.InsClass_InsClassAlu
	} else {
		insClass = pb.InsClass_InsClassAlu64
	}

	// Toss another coin to decide if we are going to do an imm alu
	// operation or one that uses a src register.
	var instr *pb.Instruction
	if rand.SharedRNG.RandRange(0, 1) == 0 {
		instr = generateImmAluInstruction(op, insClass, dstReg)
	} else {
		instr = generateRegAluInstruction(op, insClass, dstReg)
	}

	return instr
}

// RandomJmpInstruction generates a random jmp instruction that has an
// offset of at most `maxOffset` this is to minimize the possibility of a jmp
// out of the bounds of a program.
func RandomJmpInstruction(maxOffset uint64) *pb.Instruction {
	var op pb.JmpOperationCode

	// Exit, Call or JA operations require special parameters (e.g an offset
	// of 0), skip those for simplicity.
	for {
		op = RandomJumpOp()
		if IsConditional(op) {
			break
		}
	}

	var insClass pb.InsClass
	if rand.SharedRNG.OneOf(2) {
		insClass = pb.InsClass_InsClassJmp32
	} else {
		insClass = pb.InsClass_InsClassJmp
	}

	dstReg := RandomRegister()
	offset := int16(rand.SharedRNG.RandRange(1, maxOffset))
	if rand.SharedRNG.OneOf(2) {
		src := int32(rand.SharedRNG.RandRange(0, 0xffffffff))
		return newJmpInstruction(op, insClass, dstReg, src, offset)
	} else {
		src := RandomRegister()
		return newJmpInstruction(op, insClass, dstReg, src, offset)
	}
}

// RandomSize is a helper function to be used in the RandomMemInstruction
// functions. The result of this function should be one of the recognized
// operation sizes of ebpf (https://www.kernel.org/doc/html/v5.18/bpf/instruction-set.html#:~:text=The%20size%20modifier%20is%20one%20of%3A)
func RandomSize() pb.StLdSize {
	size := rand.SharedRNG.RandInt() % 4
	// The possible size values of instructions are
	// W: 0x00
	// H: 0x08
	// B: 0x10
	// DW: 0x18
	// We can generate these values with a shift to the left of 3 bits.
	size = size << 3
	return pb.StLdSize(size)
}

// Returns a random store or load instruction.
func RandomMemInstruction() *pb.Instruction {
	if rand.SharedRNG.OneOf(2) {
		return RandomStoreInstruction()
	}

	return RandomLoadInstruction()
}

func RandomStoreInstruction() *pb.Instruction {
	/*
	size := RandomSize()
	dst := RandomRegister()
	offset := int16(rand.SharedRNG.randInt())
	*/
	return nil
}

func RandomLoadInstruction() *pb.Instruction {
	return nil
}

// RandomJumpOp generates a random jump operator.
func RandomJumpOp() pb.JmpOperationCode {
	// https://docs.kernel.org/bpf/instruction-set.html#jump-instructions
	return pb.JmpOperationCode(rand.SharedRNG.RandRange(0x00, 0x0d) << 4)
}

func RandomAluOp() pb.AluOperationCode {
	// Shift by 4 bits because we need to respect the ebpf encoding:
	// https://docs.kernel.org/bpf/instruction-set.html#id6
	return pb.AluOperationCode(rand.SharedRNG.RandRange(0x00, 0x0c) << 4)
}

// IsConditional determines if the operator is not an Exit, Call or JA
// operation.
func IsConditional(op pb.JmpOperationCode) bool {
	return !(op == pb.JmpOperationCode_JmpExit || op == pb.JmpOperationCode_JmpCALL || op == pb.JmpOperationCode_JmpJA)
}

// RandomRegister returns a random register from R0 to R9.
func RandomRegister() pb.Reg {
	return pb.Reg(rand.SharedRNG.RandRange(0, 9))
}

func generateImmAluInstruction(op pb.AluOperationCode, insClass pb.InsClass, dstReg pb.Reg) *pb.Instruction {
	value := int32(rand.SharedRNG.RandRange(0, 0xFFFFFFFF))
	switch op {
	case pb.AluOperationCode_AluRsh, pb.AluOperationCode_AluLsh, pb.AluOperationCode_AluArsh:
		var maxShift = int32(64)
		if insClass == pb.InsClass_InsClassAlu {
			maxShift = 32
		}
		value = value % maxShift
		if value < 0 {
			value *= -1
		}
	case pb.AluOperationCode_AluNeg:
		value = 0
	}

	return newAluInstruction(op, insClass, dstReg, value)
}

func generateRegAluInstruction(op pb.AluOperationCode, insClass pb.InsClass, dstReg pb.Reg) *pb.Instruction {
	srcReg := RandomRegister()
	// Negation is not supported with Register as src.
	for op == pb.AluOperationCode_AluNeg {
		op = pb.AluOperationCode(rand.SharedRNG.RandRange(0x00, 0x0c) << 4)
	}

	return newAluInstruction(op, insClass, dstReg, srcReg)
}
