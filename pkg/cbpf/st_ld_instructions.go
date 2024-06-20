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

package cbpf

import (
	pb "buzzer/proto/cbpf_go_proto"
)

func newStoreLoadOperation(mode pb.StLdMode, size pb.StLdSize, class pb.InsClass, jmpTrue int8, jmpFalse int8, fieldK int32) *pb.Instruction {
	opcode := int32(0)

	// The 3 LSB are the instruction class.
	opcode |= (int32(class) & 0x07)

	// The next 2 bits are the size
	opcode |= (int32(size) & 0x18)

	// The 3 most significant bits are the mode
	opcode |= (int32(mode) & 0xE0)

	return &pb.Instruction{
		Opcode: opcode,
		Jt:     int32(jmpTrue),
		Jf:     int32(jmpFalse),
		K:      fieldK,
	}
}

// ----- Load Operations -----
// A = mem[K]
func Ld(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// A = K
func Ldi(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIMM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// A = skb->len
func LdLen(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeLEN, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// Absolute Loads
func LdAbsW(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdAbsH(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeH,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdAbsB(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// Indirect Loads
func LdIndW(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdIndH(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeH,
		pb.InsClass_InsClassLd, jt, jf, k)
}

func LdIndB(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIND, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLd, jt, jf, k)
}

// X = mem[K]
func Ldx(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// X = K
func Ldxi(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeIMM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// X = skb->len
func LdxLen(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeLEN, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// A = *((u32 *) (seccomp_data + K))
func LdxAbs(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeABS, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// X = 4*([k]&0xf)
func Ldxb(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMSH, pb.StLdSize_StLdSizeB,
		pb.InsClass_InsClassLdx, jt, jf, k)
}

// -----  Store Operations -----
// mem[k] = A
func St(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassSt, jt, jf, k)
}

// mem[k] = X
func Stx(jt int8, jf int8, k int32) *pb.Instruction {
	return newStoreLoadOperation(pb.StLdMode_StLdModeMEM, pb.StLdSize_StLdSizeW,
		pb.InsClass_InsClassStx, jt, jf, k)
}
