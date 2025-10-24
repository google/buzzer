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
	"errors"
	"fmt"
	jsonpb "github.com/golang/protobuf/jsonpb"
	protobuf "github.com/golang/protobuf/proto"
	"os"
)

func writeJsonProgram(program *pb.Program) error {
	m := &jsonpb.Marshaler{
		OrigName:     true,
		EnumsAsInts:  false,
		EmitDefaults: true,
		Indent:       "   ",
	}
	textpbData, err := m.MarshalToString(program)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "ebpf-poc-*.json")
	if err != nil {
		return err
	}

	fmt.Printf("Writing eBPF PoC %q.\n", f.Name())
	_, err = f.Write([]byte(textpbData))
	return errors.Join(err, f.Close())
}

func copyProgram(program *pb.Program) *pb.Program {
	return protobuf.Clone(program).(*pb.Program)
}

func Minimizer(program *pb.Program, bugCheckFunction func(*pb.Program) bool, footerSize int) (*pb.Program, error) {
	fmt.Println("Running minimizer...")
	minimalProgram := copyProgram(program)
	minimalProgramInstructions := DuplicateProgram(program.Functions[0].Instructions)
	if footerSize > len(minimalProgramInstructions) {
		return nil, fmt.Errorf("footerSize > len(program) (%d vs %d)", footerSize, len(minimalProgramInstructions))
	}

	minimalProgram.Functions[0].Instructions = minimalProgramInstructions
	noop := Jmp(0)

	phase1 := func() bool {
		// First step: change all instructions not contributing to the bug
		// to be noops.
		changed := true
		fmt.Println("Step 1: noop'ing instructions")
		roundCount := 1
		nooped := 0
		for changed {
			changed = false
			for i := 0; i < len(minimalProgramInstructions)-footerSize; i++ {
				fmt.Printf("\tattempting to noop instruction: %d (of %d), nooped: %d                         \r", i, len(minimalProgramInstructions), nooped)
				prev := minimalProgramInstructions[i]

				// Don't process any previous noops
				if protobuf.Equal(prev, noop) {
					continue
				}

				// Replace instruction with a noop
				minimalProgramInstructions[i] = noop
				if bugCheckFunction(minimalProgram) {
					changed = true
					nooped += 1
				} else {
					minimalProgramInstructions[i] = prev
				}
			}
			fmt.Printf("\n\tround %d finished\n", roundCount)
			roundCount += 1
		}
		return nooped != 0
	}

	phase2 := func() bool {
		changesDone := false
		// Second step: reduce the jumps to a minimum offset.
		fmt.Println("--------------------------------------")
		fmt.Println("Step 2: minimizing jumps")
		for i := 0; i < len(minimalProgramInstructions); i++ {
			insn := minimalProgramInstructions[i]
			switch insn.Opcode.(type) {
			case *pb.Instruction_JmpOpcode:
				if insn.Offset == 0 {
					continue
				}
				previousOffset := insn.Offset
				insn.Offset -= 1
				fmt.Printf("\tminimizing offset of instruction %d (initial: %d)\n", i, previousOffset)
				for bugCheckFunction(minimalProgram) && insn.Offset != 0 {
					changesDone = true
					previousOffset = insn.Offset
					insn.Offset -= 1
					fmt.Printf("\t\treducing offset to: %d              \r", insn.Offset)
				}
				fmt.Printf("\t\tfound minimal offset: %d              \n", previousOffset)
				insn.Offset = previousOffset
			default:
				continue
			}
		}
		return changesDone
	}
	phase3 := func() (bool, []*pb.Instruction) {
		fmt.Println("--------------------------------------")
		fmt.Println("Step 3: removing noop instructions")
		removed := 0
		minimalModified := []*pb.Instruction{}
		for i := 0; i < len(minimalProgramInstructions); i++ {
			insn := minimalProgramInstructions[i]
			fmt.Printf("\tattempting to remove instruction: %d, removed: %d                         \r", i, removed)
			if !protobuf.Equal(insn, noop) {
				minimalModified = append(minimalModified, insn)
				continue
			}

			candidateProgram := []*pb.Instruction{}
			if i != (len(minimalProgramInstructions) - 1) {
				candidateProgram = append(minimalModified, minimalProgramInstructions[i+1:]...)
			} else {
				candidateProgram = minimalModified
			}

			// If bug is no longer present then the instruction cannot be removed
			if !bugCheckFunction(&pb.Program{
				Functions: []*pb.Functions{
					{
						Instructions: candidateProgram,
					},
				},
				Maps: program.Maps,
			}) {
				minimalModified = append(minimalModified, insn)
			} else {
				// if the bug is present without the instruction then it can
				// be removed from the program.
				removed += 1
			}
		}
		fmt.Println()
		return removed != 0, minimalModified
	}

	changesDone := true
	iteration := 0
	for changesDone {
		fmt.Printf("> iteration: %d of minimizer\n", iteration)
		changesDone = false

		// Noop instructions.
		changes := phase1()
		changesDone = changesDone || changes

		// Reduce jumps.
		changes = phase2()
		changesDone = changesDone || changes

		// Remove noops.
		changes, minInstructions := phase3()

		changesDone = changesDone || changes
		minimalProgramInstructions = minInstructions
		minimalProgram.Functions[0].Instructions = minimalProgramInstructions

		iteration += 1
	}

	return minimalProgram, nil

}

// GeneratePoc generates a c program that can be used to reproduce fuzzer
// test cases.
func GeneratePoc(program *pb.Program, bugCheckFunction func(*pb.Program) bool, footerSize int) error {
	minimizedProgram, err := Minimizer(program, bugCheckFunction, footerSize)
	if err != nil {
		return err
	}
	return writeJsonProgram(minimizedProgram)
}
