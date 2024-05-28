package strategies

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/rand"
	"buzzer/pkg/units/units"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	"errors"
	"fmt"
)

var (
	mapCreationFailed = errors.New("Unable to create map array")
)

func NewPointerArithmeticStrategy() *PointerArithmetic {
	return &PointerArithmetic{isFinished: false}
}

// StrategyInterface contains all the methods that a fuzzing strategy should
// implement.
type PointerArithmetic struct {
	isFinished        bool
	mapFd             int
	programCount      int
	validProgramCount int
}

// GenerateProgram should return the instructions to feed the verifier.
func (pa *PointerArithmetic) GenerateProgram(ffi *units.FFI) (*epb.Program, error) {
	pa.programCount += 1
	fmt.Printf("Generated %d programs, %d were valid               \r", pa.programCount, pa.validProgramCount)

	// header contains the initialization of all registers with random values.
	header, err := InstructionSequence(
		Mov64(R0, int32(rand.SharedRNG.RandInt())),
		Mov64(R1, int32(rand.SharedRNG.RandInt())),
		Mov64(R2, int32(rand.SharedRNG.RandInt())),
		Mov64(R3, int32(rand.SharedRNG.RandInt())),
		Mov64(R4, int32(rand.SharedRNG.RandInt())),
		Mov64(R5, int32(rand.SharedRNG.RandInt())),
		Mov64(R6, int32(rand.SharedRNG.RandInt())),
		Mov64(R7, int32(rand.SharedRNG.RandInt())),
		Mov64(R8, int32(rand.SharedRNG.RandInt())),
		Mov64(R9, int32(rand.SharedRNG.RandInt())),
	)

	if err != nil {
		return nil, err
	}

	// Generate an arbitrary number of random alu and jmp instructions
	// as body.
	instructionCount := rand.SharedRNG.RandInt() % 1000
	body := []*epb.Instruction{}
	for instructionCount != 0 {
		instructionCount -= 1
		var instruction *epb.Instruction
		// The last instruction should not be a jmp otherwise we will jump over the first
		// instruction of the footer.
		if rand.SharedRNG.RandRange(1, 100) > 30 || instructionCount == 0 {
			instruction = RandomAluInstruction()
		} else {
			instruction = RandomJmpInstruction(uint64(instructionCount))
		}
		body = append(body, instruction)
	}

	// For the footer, write a control and test value to a map, control will
	// not do ptr arithmetic, test will attempt to do some and see if the
	// verifier thinks its safe. We will validate this assumption in onExecuteDone.
	ffi.CloseFD(pa.mapFd)
	pa.mapFd = ffi.CreateMapArray(2)
	if pa.mapFd < 0 {
		return nil, mapCreationFailed
	}

	footer, err := InstructionSequence(
		// Select a random register and store its value in R8.
		Mov64(R8, RandomRegister()),

		// Load a fd to the map.
		LdMapByFd(R9, pa.mapFd),

		// Begin by writing a value to the map without ptr arithmetic.
		// 0 here is the index to the map element.
		// https://man7.org/linux/man-pages/man7/bpf-helpers.7.html#:~:text=void%20*bpf_map_lookup_elem(struct%20bpf_map%20*map%2C%20const%20void%20*key)
		StW(R10, 0, -4),
		Mov64(R2, R10),
		Add64(R2, -4),
		Mov64(R1, R9),
		Call(MapLookup),
		JmpNE(R0, 0, 1),
		Exit(),
		StDW(R0, 0xCAFE, 0),

		// Now repeat the operation but doing pointer arithmetic.
		StW(R10, 1, -4),
		Mov64(R2, R10),
		Add64(R2, -4),
		Mov64(R1, R9),
		Call(MapLookup),
		JmpNE(R0, 0, 1),
		Exit(),

		// Do math with the random register selected at the start.
		Add64(R0, R8),
		StDW(R0, 0xCAFE, 0),

		// Exit
		Mov64(R0, 0),
		Exit(),
	)

	if err != nil {
		return nil, err
	}
	header = append(header, body...)
	header = append(header, footer...)
	p := &epb.Program{
		Instructions: header,
	}
	return p, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (pa *PointerArithmetic) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	if pa.programCount%500 == 0 {
		fmt.Println(verificationResult.VerifierLog)
	}
	if verificationResult.IsValid {
		pa.validProgramCount += 1
	}
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (pa *PointerArithmetic) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	mapElements, err := ffi.GetMapElements(pa.mapFd, 2)
	if err != nil {
		fmt.Println(err)
		return true
	}

	return mapElements.Elements[0] == mapElements.Elements[1]
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (pa *PointerArithmetic) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (pa *PointerArithmetic) IsFuzzingDone() bool {
	return pa.isFinished
}

// StrategyName is used for strategy selection via runtime flags.
func (pg *PointerArithmetic) Name() string {
	return "pointer_arithmetic"
}
