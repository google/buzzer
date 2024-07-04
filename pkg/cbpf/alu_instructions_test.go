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
	"testing"
)

func TestAluInstructionGenerationAndEncoding(t *testing.T) {
	testK := int32(65535)
	tests := []struct {
		testName             string
		instruction          *pb.Instruction
		wantInstructionClass int32
		wantSrc              int32
		wantOperationCode    int32
		wantJmpTrue          int32
		wantJmpFalse         int32
		wantK                int32
	}{
		{
			testName:             "Add with Register as Source",
			instruction:          Add(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluAdd),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Add with Int as Source",
			instruction:          Add(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluAdd),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Sub Register as Source",
			instruction:          Sub(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluSub),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Sub with Int as Source",
			instruction:          Sub(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluSub),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Mul with Register as Source",
			instruction:          Mul(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluMul),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Mul with Int as Source",
			instruction:          Mul(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluMul),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Div with Register as Source",
			instruction:          Div(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluDiv),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Div with Int as Source",
			instruction:          Div(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluDiv),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Or with Register as Source",
			instruction:          Or(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluOr),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Or with Int as Source",
			instruction:          Or(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluOr),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "And with Register as Source",
			instruction:          And(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluAnd),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "And with Int as Source",
			instruction:          And(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluAnd),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Lsh with Register as Source",
			instruction:          Lsh(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluLsh),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Lsh with Int as Source",
			instruction:          Lsh(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluLsh),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Rsh with Register as Source",
			instruction:          Rsh(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluRsh),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Rsh with Int as Source",
			instruction:          Rsh(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluRsh),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Neg with Register as Source",
			instruction:          Neg(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluNeg),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Neg with Int as Source",
			instruction:          Neg(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluNeg),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Mod with Register as Source",
			instruction:          Mod(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluMod),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Mod with Int as Source",
			instruction:          Mod(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluMod),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Xor with Register as Source",
			instruction:          Xor(X),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(pb.AluOperationCode_AluXor),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
		{
			testName:             "Xor with Int as Source",
			instruction:          Xor(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassAlu),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(pb.AluOperationCode_AluXor),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Return with Register as Source",
			instruction:          Ret(A),
			wantInstructionClass: int32(pb.InsClass_InsClassRet),
			wantSrc:              int32(pb.SrcOperand_RegSrc),
			wantOperationCode:    int32(0x00),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(A),
		},
		{
			testName:             "Return with Int as Source",
			instruction:          Ret(testK),
			wantInstructionClass: int32(pb.InsClass_InsClassRet),
			wantSrc:              int32(pb.SrcOperand_Immediate),
			wantOperationCode:    int32(0x00),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                testK,
		},
		{
			testName:             "Misc TAX",
			instruction:          Misc(A),
			wantInstructionClass: int32(pb.InsClass_InsClassMisc),
			wantSrc:              int32(0x00),
			wantOperationCode:    int32(0x00),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(A),
		},
		{
			testName:             "Misc TXA",
			instruction:          Misc(X),
			wantInstructionClass: int32(pb.InsClass_InsClassMisc),
			wantSrc:              int32(0x00),
			wantOperationCode:    int32(0x80),
			wantJmpTrue:          0,
			wantJmpFalse:         0,
			wantK:                int32(X),
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			instruction := tc.instruction
			t.Logf("Running test case %s", tc.testName)

			// The LSB are the instruction class
			ocClass := instruction.Opcode & 0x07

			// The fourth bit is the source operand
			ocSrc := instruction.Opcode & 0x08

			// The 4 MSB are the operation code
			ocCode := instruction.Opcode & 0xf0

			if ocClass != tc.wantInstructionClass {
				t.Fatalf("instruction.Opcode Class = %d, want %d", ocClass, tc.wantInstructionClass)
			}

			if ocSrc != tc.wantSrc {
				t.Fatalf("instruction.Opcode Source = %d, want %d", ocSrc, tc.wantSrc)
			}

			if ocCode != tc.wantOperationCode {
				t.Fatalf("instruction.Opcode Code = %d, want %d", ocCode, tc.wantOperationCode)
			}

			if instruction.Jt != tc.wantJmpTrue {
				t.Fatalf("instruction.jt = %d, want %d", instruction.Jt, tc.wantJmpTrue)
			}

			if instruction.Jf != tc.wantJmpFalse {
				t.Fatalf("instruction.jf = %d, want %d", instruction.Jf, tc.wantJmpFalse)
			}

			if instruction.K != tc.wantK {
				t.Fatalf("instruction.k = %d, want %d", instruction.K, tc.wantK)
			}
		})
	}
}
