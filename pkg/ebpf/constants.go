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

const (
	// 'code' values for ALU operations
	// opcode values taken from
	// https://docs.kernel.org/bpf/instruction-set.html#arithmetic-and-jump-instructions
	// AluAdd Add operation.
	AluAdd = 0x00
	// AluSub Sub operation.
	AluSub = 0x10
	// AluMul Mul operation.
	AluMul = 0x20
	// AluDiv Div operation.
	AluDiv = 0x30
	// AluOr Or operation.
	AluOr = 0x40
	// AluAnd And operation.
	AluAnd = 0x50
	// AluLsh Lsh operation.
	AluLsh = 0x60
	// AluRsh Rsh operation.
	AluRsh = 0x70
	// AluNeg Neg operation.
	AluNeg = 0x80
	// AluMod Mod operation.
	AluMod = 0x90
	// AluXor Xor operation.
	AluXor = 0xa0
	// AluMov Mov operation.
	AluMov = 0xb0
	// AluArsh Arsh operation.
	AluArsh = 0xc0
	// AluEnd End operation.
	AluEnd = 0xd0

	// eBPF Jmp instructions
	// JmpJA JA operation.
	JmpJA = 0x00
	// JmpJEQ JEQ operation.
	JmpJEQ = 0x10
	// JmpJGT JGT operation.
	JmpJGT = 0x20
	// JmpJGE JGE operation.
	JmpJGE = 0x30
	// JmpJSET JSET operation.
	JmpJSET = 0x40
	// JmpJNE JNE operation.
	JmpJNE = 0x50
	// JmpJSGT JSGT operation.
	JmpJSGT = 0x60
	// JmpJSGE JSGE operation.
	JmpJSGE = 0x70
	// JmpCALL CALL operation.
	JmpCALL = 0x80
	// JmpExit Exit operation.
	JmpExit = 0x90
	// JmpJLT JLT operation.
	JmpJLT = 0xa0
	// JmpJLE JLE operation.
	JmpJLE = 0xb0
	// JmpJSLT JSLT operation.
	JmpJSLT = 0xc0
	// JmpJSLE JSLE operation.
	JmpJSLE = 0xd0

	// eBPF instruction classes
	// InsClassLd Ld instruction class.
	InsClassLd = 0x00
	// InsClassLdx Ldx instruction class.
	InsClassLdx = 0x01
	// InsClassSt St instruction class.
	InsClassSt = 0x02
	// InsClassStx Stx instruction class.
	InsClassStx = 0x03
	// InsClassAlu Alu instruction class.
	InsClassAlu = 0x04
	// InsClassJmp Jmp instruction class.
	InsClassJmp = 0x05
	// InsClassJmp32 Jmp32 instruction class.
	InsClassJmp32 = 0x06
	// InsClassAlu64 Alu64 instruction class.
	InsClassAlu64 = 0x07

	// eBPF Load and Store mode modifiers
	// StLdModeIMM IMM Load Mode.
	StLdModeIMM = 0x00
	// StLdModeABS ABS Load Mode.
	StLdModeABS = 0x20
	// StLdModeIND IND Load Mode.
	StLdModeIND = 0x40
	// StLdModeMEM MEM Load Mode.
	StLdModeMEM = 0x60
	// StLdModeATOMIC ATOMIC Load Mode.
	StLdModeATOMIC = 0xc0

	// eBPF Load and Store Size modifiers
	// StLdSizeW W Size Modifier.
	StLdSizeW = 0x00
	// StLdSizeH H Size Modifier.
	StLdSizeH = 0x08
	// StLdSizeB B Size Modifier.
	StLdSizeB = 0x10
	// StLdSizeDW DW Size Modifier.
	StLdSizeDW = 0x18
)

// Values for the eBPF Registers
var RegR0 = &Register{registerNumber: 0}
var RegR1 = &Register{registerNumber: 1}
var RegR2 = &Register{registerNumber: 2}
var RegR3 = &Register{registerNumber: 3}
var RegR4 = &Register{registerNumber: 4}
var RegR5 = &Register{registerNumber: 5}
var RegR6 = &Register{registerNumber: 6}
var RegR7 = &Register{registerNumber: 7}
var RegR8 = &Register{registerNumber: 8}
var RegR9 = &Register{registerNumber: 9}
var RegR10 = &Register{registerNumber: 10}

// This gets used when specifying a file descriptor with pseudo instructions.
// The value gets specified in the src reg therefore we need to declare it as
// a register object... the value is 1 so a reference to RegR1 will do the job.
var PseudoMapFD = RegR1

const (
	// RegisterCount is the number of registers available
	RegisterCount = 10
)

const (
	// Constants related to the encoding of ebpf operations
	// UnusedField Unused Field.
	UnusedField = 0x00
	// SrcImm take src as an imm value.
	SrcImm = 0x00
	// SrcReg take src as a reg value.
	SrcReg = 0x08
)

const (
	// ebpf helper function codes
	// MapLookup Map Lookup helper function.
	MapLookup            = 0x01
	SkbLoadBytesRelative = 0x44
)
