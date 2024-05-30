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

func AlignmentForSize(s pb.StLdSize) int16 {
	switch s {
	case pb.StLdSize_StLdSizeB:
		return 1
	case pb.StLdSize_StLdSizeH:
		return 2
	case pb.StLdSize_StLdSizeW:
		return 4
	case pb.StLdSize_StLdSizeDW:
		return 8
	default:
		// We shouldn't reach this.
		return 0
	}
}

func RandomOffset(s pb.StLdSize) int16 {
	// Cap offsets to 512.
	maxOffset := int16(512)
	offset := int16(rand.SharedRNG.RandInt()) % maxOffset
	for offset == 0 {
		offset = int16(rand.SharedRNG.RandInt()) % maxOffset
	}

	if offset > 0 {
		// Mem offsets from the stack can only be negative.
		offset = offset * -1
	}

	// Align the offset according to the size.
	for offset%AlignmentForSize(s) != 0 {
		offset = offset - 1
	}

	return offset
}

// Returns a random store or load instruction to the stack.
func RandomMemInstruction() *pb.Instruction {
	t := rand.SharedRNG.RandInt() % 3
	switch t {
	case 0:
		return RandomStoreInstruction()
	case 1:
		return RandomLoadInstruction()
	default:
		return RandomAtomicInstruction()
	}

}

func RandomAtomicInstruction() *pb.Instruction {
	src := RandomRegister()
	validSizes := []pb.StLdSize{pb.StLdSize_StLdSizeW, pb.StLdSize_StLdSizeDW}
	size := validSizes[rand.SharedRNG.RandInt()%2]
	offset := RandomOffset(size)
	validOperations := []pb.AluOperationCode{pb.AluOperationCode_AluAdd, pb.AluOperationCode_AluAnd, pb.AluOperationCode_AluOr, pb.AluOperationCode_AluXor}
	operation := validOperations[rand.SharedRNG.RandInt()%4]
	return newAtomicInstruction(R10, src, size, offset, int32(operation))
}

func RandomStoreInstruction() *pb.Instruction {
	size := RandomSize()
	offset := RandomOffset(size)

	// Decide if we are doing a Store from a register or a constant.
	if rand.SharedRNG.OneOf(2) {
		// Constant
		imm := int32(rand.SharedRNG.RandInt())
		return newStoreOperation(size, R10, imm, offset)
	}

	// Register
	src := RandomRegister()
	return newStoreOperation(size, R10, src, offset)
}

func RandomLoadInstruction() *pb.Instruction {
	size := RandomSize()
	offset := RandomOffset(size)
	dst := RandomRegister()
	return newLoadOperation(size, dst, R10, offset)
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
