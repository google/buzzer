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

func newStoreLoadOperation(mode pb.StLdMode, size pb.StLdSize, class pb.InsClass, jmpTrue, jmpFalse, fieldK int32) *pb.Instruction {

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
		Jt:     jmpTrue,
		Jf:     jmpFalse,
		K:      fieldK,
	}
}

// ----- Load Operations -----
// A = mem[K]
func Ld(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// A = K
func Ldi(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIMM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// A = skb->len
func LdLen(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeLEN, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// Absolute Loads
func LdAbsW(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdAbsH(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeH,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdAbsB(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// Indirect Loads
func LdIndW(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdIndH(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeH,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdIndB(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// X = mem[K]
func Ldx(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// X = K
func Ldxi(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIMM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// X = skb->len
func LdxLen(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeLEN, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// A = *((u32 *) (seccomp_data + K))
func LdxAbs(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// X = 4*([k]&0xf)
func Ldxb(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMSH, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// -----  Store Operations -----
// mem[k] = A
func St(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassSt, jt, jf, k)
}

// mem[k] = X
func Stx(jt, jf, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassStx, jt, jf, k)
}
