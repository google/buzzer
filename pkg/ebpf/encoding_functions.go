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

// ALU opcode byte is encoded as follows"
// 4 bit (MSB) 	- operation code
// 1 bit 				- source (0 immediate operation, 1 for a source register)
// 3 bit				- Instruction class (64bit or 32bit)

// This function applies the ALU operation stored in `op` with an `immediate` value to `dstReg`.
// `aluInstruction“ class must be either `EbpfInsClassAlu“ or `EbpfInsClassAlu64`.
// For example:
// `op` = `EbpfAluAdd`, `aluInstructionClass`, `dstReg` = `EBPF_REGISTER_3`, `immediate` = `1337`
// maps to the encoded eBPF operation:
// dst_reg += int32(immediate)
func encodeImmediateAluInstruction(op, instructionClass uint8, dstReg uint8, immediate int32) uint64 {
	opcode := encodeAluOrJmpOpcode(instructionClass, SrcImm, op)
	return encodeEbpfInstruction(opcode, UnusedField, dstReg, UnusedField, immediate)
}

func encodeRegisterAluInstruction(op, instructionClass uint8, dstReg, srcReg uint8) uint64 {
	opcode := encodeAluOrJmpOpcode(instructionClass, SrcReg, op)
	return encodeEbpfInstruction(opcode, srcReg, dstReg, UnusedField, UnusedField)
}

func encodeImmediateJmpInstruction(op, instructionClass, dstReg uint8, immediate int32, offset int16) uint64 {
	opcode := encodeAluOrJmpOpcode(instructionClass, SrcImm, op)
	return encodeEbpfInstruction(opcode, UnusedField, dstReg, offset, immediate)
}

func encodeRegisterJmpInstruction(op, instructionClass, dstReg, srcReg uint8, offset int16) uint64 {
	opcode := encodeAluOrJmpOpcode(instructionClass, SrcReg, op)
	return encodeEbpfInstruction(opcode, srcReg, dstReg, offset, UnusedField)
}

func encodeImmediateStOrLdInstruction(instrClass, size, mode, dstReg, srcReg uint8, immediate int32, offset int16) uint64 {
	opcode := encodeStoreOrLoadOpcode(instrClass, size, mode)
	return encodeEbpfInstruction(opcode, srcReg, dstReg, offset, immediate)
}

func encodeAluOrJmpOpcode(class, src, operation uint8) uint8 {
	opcode := uint8(0)

	// The 3 least significant bits are the instruction class.
	opcode |= (class & 0x07)

	// The fourth bit is the source operand.
	opcode |= (src & 0x08)

	// Finally the 4 MSB are the operation code.
	opcode |= (operation & 0xF0)

	return opcode
}

func encodeStoreOrLoadOpcode(class, size, mode uint8) uint8 {
	opcode := uint8(0)

	// The 3 LSB are the instruction class.
	opcode |= (class & 0x07)

	// The next 2 bits are the size
	opcode |= (size & 0x18)

	// The 3 most significant bits are the mode
	opcode |= (mode & 0xE0)

	return opcode
}

// To understand what each part of the encoding mean, please refer to
// http://shortn/_mFOBeQLg2s.
func encodeEbpfInstruction(opcode uint8, srcReg, dstReg uint8, offset int16, immediate int32) uint64 {
	encoding := uint64(0)

	// The first 8 bits are the opcode.
	encoding |= uint64(opcode)

	// The LSB of the registers portion of the encoding is the destination
	// register.
	registers := uint8(dstReg & 0x0F)

	// And the MSB are the source register.
	registers |= ((srcReg & 0x0F) << 4)

	encoding |= uint64(uint16(registers) << 8)

	encoding |= uint64(uint32(offset) << 16)

	encoding |= (uint64(immediate) << 32)
	return encoding
}

// NameForAluInstruction returns the C macro name of the provided alu
// instruction. This is useful to generate the PoC of a program.
func NameForAluInstruction(instr uint8) string {
	switch instr {
	case AluAdd:
		return "BPF_ADD"
	case AluSub:
		return "BPF_SUB"
	case AluMul:
		return "BPF_MUL"
	case AluDiv:
		return "BPF_DIV"
	case AluOr:
		return "BPF_OR"
	case AluAnd:
		return "BPF_AND"
	case AluLsh:
		return "BPF_LSH"
	case AluRsh:
		return "BPF_RSH"
	case AluNeg:
		return "BPF_NEG"
	case AluMod:
		return "BPF_MOD"
	case AluXor:
		return "BPF_XOR"
	case AluMov:
		return "BPF_MOV"
	case AluArsh:
		return "BPF_ARSH"
	case AluEnd:
		return "BPF_END"
	default:
		return fmt.Sprintf("unknown instruction: %d", instr)

	}
}

// NameForJmpInstruction returns the C macro name of the provided jmp
// instruction. This is useful to generate the PoC of a program.
func NameForJmpInstruction(instr uint8) string {
	switch instr {
	case JmpJA:
		return "BPF_JA"
	case JmpJEQ:
		return "BPF_JEQ"
	case JmpJGT:
		return "BPF_JGT"
	case JmpJGE:
		return "BPF_JGE"
	case JmpJSET:
		return "BPF_JSET"
	case JmpJNE:
		return "BPF_JNE"
	case JmpJSGT:
		return "BPF_JSGT"
	case JmpJSGE:
		return "BPF_JSGE"
	case JmpCALL:
		return "BPF_CALL"
	case JmpExit:
		return "BPF_EXIT"
	case JmpJLT:
		return "BPF_JLT"
	case JmpJLE:
		return "BPF_JLE"
	case JmpJSLT:
		return "BPF_JSLT"
	case JmpJSLE:
		return "BPF_JSLE"
	default:
		return fmt.Sprintf("unknown instruction: %d", instr)

	}
}

// GetBpfFuncName returns the C macro name of the provided bpf helper function.
func GetBpfFuncName(funcNumber int32) string {
	switch funcNumber {
	case MapLookup:
		return "BPF_FUNC_map_lookup_elem"
	default:
		return "unknown"
	}
}
