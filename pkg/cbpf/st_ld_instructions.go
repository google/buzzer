// Copyright 2024 Google LLC
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

package cbpf

import (
	pb "buzzer/proto/cbpf_go_proto"
)

func newStoreLoadOperation(mode pb.StLdMode, size pb.StLdSize, class pb.InsClass, fieldK int32) *pb.Instruction {

	// The opcode field is divided into three parts, for more information go to:
	// https://www.infradead.org/~mchehab/kernel_docs/networking/filter.html#ebpf-opcode-encoding
	opcode := int32(0)

	// The 3 LSB are the instruction class.
	opcode |= (int32(class) & 0x07)

	// The next 2 bits are the size
	opcode |= (int32(size) & 0x18)

	// The 3 most significant bits are the mode
	opcode |= (int32(mode) & 0xE0)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     0,
		Jf:     0,
		K:      fieldK,
	}
}

// ----- Load Operations -----
// A = mem[K]
func Ld(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, k)
}

// A = K
func Ldi(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIMM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, k)
}

// A = skb->len
func LdLen(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeLEN, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, k)
}

// Absolute Loads
func LdAbsW(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, k)
}

func LdAbsH(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeH,
		pb.InsClass_InsClassLd, k)
}

func LdAbsB(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLd, k)
}

// Indirect Loads
func LdIndW(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, k)
}

func LdIndH(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeH,
		pb.InsClass_InsClassLd, k)
}

func LdIndB(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLd, k)
}

// X = mem[K]
func Ldx(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, k)
}

// X = K
func Ldxi(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIMM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, k)
}

// X = skb->len
func LdxLen(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeLEN, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, k)
}

// A = *((u32 *) (seccomp_data + K))
func LdxAbs(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, k)
}

// X = 4*([k]&0xf)
func Ldxb(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMSH, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLdx, k)
}

// -----  Store Operations -----
// mem[k] = A
func St(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassSt, k)
}

// mem[k] = X
func Stx(k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassStx, k)
}
