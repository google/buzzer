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
	"testing"
)

type MockGenerator struct {
	generateInvoked                bool
	generateNextInstructionInvoked bool
}

func (g *MockGenerator) Generate(a *Program) Operation {
	g.generateInvoked = true
	return g.GenerateNextInstruction(a)
}

func (g *MockGenerator) GenerateNextInstruction(a *Program) Operation {
	g.generateNextInstructionInvoked = true
	reg0 := MovRegImm64(RegR0, 0)
	reg0.SetNextInstruction(ExitOperation())
	a.MarkRegisterInitialized(RegR0.RegisterNumber())
	return reg0
}

func NewTestProgram(gen *MockGenerator) *Program {
	prog := &Program{
		logMap:      0,
		Gen:         gen,
		MapSize:     0,
		MinRegister: RegR0.RegisterNumber(),
		MaxRegister: RegR10.RegisterNumber(),
	}
	prog.construct()
	return prog
}

func TestProgramGeneration(t *testing.T) {
	gen := &MockGenerator{
		generateInvoked:                false,
		generateNextInstructionInvoked: false,
	}
	a := NewTestProgram(gen)
	if !gen.generateInvoked {
		t.Errorf("Expected Generate() to be invoked")
	}

	if !gen.generateNextInstructionInvoked {
		t.Errorf("Expected GenerateNextInstruction to be invoked")
	}
	if !a.IsRegisterInitialized(RegR0.RegisterNumber()) {
		t.Errorf("expected R0 to be marked as initialized\n")
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
