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
	"reflect"
	"testing"
)

func NewTestProgram(insts []Instruction) *Program {
	prog := &Program{
		logMap:       0,
		MapSize:      0,
		Instructions: insts,
		MinRegister:  RegR0.RegisterNumber(),
		MaxRegister:  RegR9.RegisterNumber(),
	}
	return prog
}

func TestProgramGeneration(t *testing.T) {
	insts, _ := InstructionSequence(Mov64(RegR0, 0), Exit())
	a := NewTestProgram(insts)

	if !reflect.DeepEqual(insts, a.Instructions) {
		t.Fatalf("program Instructions array is different than the one supplied.")
	}

	a.MarkRegisterInitialized(RegR0.RegisterNumber())

	if !a.IsRegisterInitialized(RegR0.RegisterNumber()) {
		t.Errorf("expected R0 to be marked as initialized\n")
	}

	a.MarkRegisterInitialized(RegR10.RegisterNumber())

	if a.IsRegisterInitialized(RegR10.RegisterNumber()) {
		t.Errorf("RegR10 is outside of the range of tracked registers and should not be marked initialized\n")
	}

	expectedBytecode := []uint64{0x000000000000b7, 0x00000000000095}
	actualBytecode := a.GenerateBytecode()
	if len(expectedBytecode) != len(actualBytecode) {
		t.Errorf("want len(bytecode) = %d, have %d", len(expectedBytecode), len(actualBytecode))
	}

	for i := 0; i < len(actualBytecode); i++ {
		if actualBytecode[i] != expectedBytecode[i] {
			t.Errorf("want bytecode = %v, have %v", expectedBytecode, actualBytecode)
		}
	}
}
