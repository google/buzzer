package strategies

import (
	. "buzzer/pkg/cbpf/cbpf"
	"buzzer/pkg/rand"
	"buzzer/pkg/units/units"
	cpb "buzzer/proto/cbpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
	"fmt"
)

func NewCbpfRandomInstructionStrategy() *cBPFRandomInstruction {
	return &cBPFRandomInstruction{isFinished: false}
}

type cBPFRandomInstruction struct {
	isFinished        bool
	programCount      int
	validProgramCount int
}

func (cr *cBPFRandomInstruction) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {
	cr.programCount += 1
	fmt.Printf("Generated %d programs, %d were valid               \r", cr.programCount, cr.validProgramCount)

	instructionCount := rand.SharedRNG.RandInt() % 1000
    instructions := []*cpb.Instruction{Add(1), Misc(A)} // Initialize Registers
	for instructionCount != 0 {
		instructionCount -= 1
		var instruction *cpb.Instruction
		t := rand.SharedRNG.RandInt() % 4
		switch t {
		case 0:
			instruction = RandomStoreInstruction()
		case 1:
			instruction = RandomLoadInstruction()
		case 2:
			if instructionCount != 0 {
				instruction = RandomJmpInstruction(uint64(instructionCount))
			} else {
				instruction = RandomAluInstruction()
			}
		default:
			instruction = RandomAluInstruction()
		}
		instructions = append(instructions, instruction)
	}

	instructions = append(instructions, Ret(4))

	prog := &pb.Program{
		Program: &pb.Program_Cbpf{
			Cbpf: &cpb.Program{
				Instructions: instructions,
			},
		}}
	return prog, nil
}

func (cr *cBPFRandomInstruction) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	if verificationResult.IsValid {
		cr.validProgramCount += 1
	}
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (cr *cBPFRandomInstruction) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	return true
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (cr *cBPFRandomInstruction) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (cr *cBPFRandomInstruction) IsFuzzingDone() bool {
	return cr.isFinished
}

// StrategyName is used for strategy selection via runtime flags.
func (pg *cBPFRandomInstruction) Name() string {
	return "cbpf_random_instruction"
}
