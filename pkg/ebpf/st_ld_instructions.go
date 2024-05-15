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
	pb "buzzer/proto/ebpf_go_proto"
)

func newStoreOperation[T Src](size pb.StLdSize, dst pb.Reg, src T, offset int16) *pb.Instruction {
	var srcReg pb.Reg
	var imm int32
	var class pb.InsClass
	mode := pb.StLdMode_StLdModeMEM
	switch any(src).(type) {
	case pb.Reg:
		srcReg = any(src).(pb.Reg)
		imm = 0
		class = pb.InsClass_InsClassStx
	case int:
		srcReg = pb.Reg_R0
		intImm := any(src).(int)
		imm = int32(intImm)
		class = pb.InsClass_InsClassSt
	default:
		srcReg = pb.Reg_R0
		imm = any(src).(int32)
		class = pb.InsClass_InsClassSt
	}
	return &pb.Instruction{
		Opcode: &pb.Instruction_MemOpcode{
			MemOpcode: &pb.MemOpcode{
				Mode:             mode,
				Size:             size,
				InstructionClass: class,
			},
		},
		DstReg: dst,
		SrcReg: srcReg,
		// Oh protobuf why don't you have int16 support?, need to cast
		// this to int32 to make golang happy.
		Offset:    int32(offset),
		Immediate: imm,
		PseudoInstruction: &pb.Instruction_Empty{
			Empty: &pb.Empty{},
		},
	}
}

// StDW Stores 8 byte data from `src` into `dst`
func StDW[T Src](dst pb.Reg, src T, offset int16) *pb.Instruction {
	return newStoreOperation(pb.StLdSize_StLdSizeDW, dst, src, offset)
}

// StDW Stores 4 byte data from `src` into `dst`
func StW[T Src](dst pb.Reg, src T, offset int16) *pb.Instruction {
	return newStoreOperation(pb.StLdSize_StLdSizeW, dst, src, offset)
}

// StH Stores 2 byte (Half word) data from `src` into `dst`
func StH[T Src](dst pb.Reg, src T, offset int16) *pb.Instruction {
	return newStoreOperation(pb.StLdSize_StLdSizeH, dst, src, offset)
}

// StB Stores 1 byte data from `src` into `dst`
func StB[T Src](dst pb.Reg, src T, offset int16) *pb.Instruction {
	return newStoreOperation(pb.StLdSize_StLdSizeB, dst, src, offset)
}

func newLoadMemOperation[T Src](size pb.StLdSize, dst pb.Reg, src T, offset int16) *pb.Instruction {
	var srcReg pb.Reg
	var imm int32
	var class pb.InsClass
	switch any(src).(type) {
	case pb.Reg:
		srcReg = any(src).(pb.Reg)
		class = pb.InsClass_InsClassLdx
		imm = 0
	case int:
		srcReg = pb.Reg_R0
		intImm := any(src).(int)
		imm = int32(intImm)
		class = pb.InsClass_InsClassSt
	default:
		srcReg = pb.Reg_R0
		class = pb.InsClass_InsClassLd
		imm = any(src).(int32)
	}

	// This if is needed because the underlying interface of
	// PseudoInstruction is not exported outside of the proto.
	return &pb.Instruction{
		Opcode: &pb.Instruction_MemOpcode{
			MemOpcode: &pb.MemOpcode{
				Mode:             pb.StLdMode_StLdModeMEM,
				Size:             size,
				InstructionClass: class,
			},
		},
		DstReg: dst,
		SrcReg: srcReg,
		// Oh protobuf why don't you have int16 support?, need to cast
		// this to int32 to make golang happy.
		Offset:    int32(offset),
		Immediate: imm,
		PseudoInstruction: &pb.Instruction_Empty{
			Empty: &pb.Empty{},
		},
	}
}

func newLoadImmOperation(size pb.StLdSize, dst pb.Reg, src pb.Reg, offset int16, imm int32, pseudoIns *uint64) *pb.Instruction {
	class := pb.InsClass_InsClassLd
	ret := &pb.Instruction{
		Opcode: &pb.Instruction_MemOpcode{
			MemOpcode: &pb.MemOpcode{
				Mode:             pb.StLdMode_StLdModeIMM,
				Size:             size,
				InstructionClass: class,
			},
		},
		DstReg: dst,
		SrcReg: src,
		// Oh protobuf why don't you have int16 support?, need to cast
		// this to int32 to make golang happy.
		Offset:            int32(offset),
		Immediate:         imm,
		PseudoInstruction: nil,
	}

	if pseudoIns != nil {
		ret.PseudoInstruction = &pb.Instruction_PseudoValue{
			PseudoValue: *pseudoIns,
		}
	} else {
		ret.PseudoInstruction = &pb.Instruction_Empty{
			Empty: &pb.Empty{},
		}
	}

	return ret
}

// LdDW Stores 8 byte data from `src` into `dst`
func LdDW(dst pb.Reg, src pb.Reg, offset int16) *pb.Instruction {
	return newLoadMemOperation(pb.StLdSize_StLdSizeDW, dst, src, offset)
}

// LdW Stores 4 byte data from `src` into `dst`
func LdW(dst pb.Reg, src pb.Reg, offset int16) *pb.Instruction {
	return newLoadMemOperation(pb.StLdSize_StLdSizeW, dst, src, offset)
}

// LdH Stores 2 byte (Half word) data from `src` into `dst`
func LdH(dst pb.Reg, src pb.Reg, offset int16) *pb.Instruction {
	return newLoadMemOperation(pb.StLdSize_StLdSizeH, dst, src, offset)
}

// LdB Stores 1 byte data from `src` into `dst`
func LdB(dst pb.Reg, src pb.Reg, offset int16) *pb.Instruction {
	return newLoadMemOperation(pb.StLdSize_StLdSizeB, dst, src, offset)
}

func LdMapByFd(dst pb.Reg, fd int) *pb.Instruction {
	pseudoIns := uint64(0)
	return newLoadImmOperation(pb.StLdSize_StLdSizeDW, dst, PseudoMapFD, UnusedField, int32(fd), &pseudoIns)
}

func newAtomicInstruction(dst, src pb.Reg, size pb.StLdSize, offset int16, operation int32) *pb.Instruction {
	class := pb.InsClass_InsClassStx

	// This if is needed because the underlying interface of
	// PseudoInstruction is not exported outside of the proto.
	return &pb.Instruction{
		Opcode: &pb.Instruction_MemOpcode{
			MemOpcode: &pb.MemOpcode{
				Mode:             pb.StLdMode_StLdModeATOMIC,
				Size:             size,
				InstructionClass: class,
			},
		},
		DstReg: dst,
		SrcReg: src,
		// Oh protobuf why don't you have int16 support?, need to cast
		// this to int32 to make golang happy.
		Offset:    int32(offset),
		Immediate: operation,
		PseudoInstruction: &pb.Instruction_Empty{
			Empty: &pb.Empty{},
		},
	}
}

func MemAdd64(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeDW, offset, int32(pb.AluOperationCode_AluAdd))
}

func MemAdd(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeW, offset, int32(pb.AluOperationCode_AluAdd))
}

func MemOr64(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeDW, offset, int32(pb.AluOperationCode_AluOr))
}

func MemOr(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeW, offset, int32(pb.AluOperationCode_AluOr))
}

func MemAnd64(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeDW, offset, int32(pb.AluOperationCode_AluAnd))
}

func MemAnd(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeW, offset, int32(pb.AluOperationCode_AluAnd))
}

func MemXor64(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeDW, offset, int32(pb.AluOperationCode_AluXor))
}

func MemXor(dst, src pb.Reg, offset int16) *pb.Instruction {
	return newAtomicInstruction(dst, src, pb.StLdSize_StLdSizeW, offset, int32(pb.AluOperationCode_AluXor))
}
