package strategies

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/rand"
	"buzzer/pkg/units/units"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
	"errors"
	"fmt"
	protobuf "github.com/golang/protobuf/proto"
)

var (
	unknownOperation = errors.New("Unknown mutation operation")
)

// These constants are used to decide which type of operations to generate.
const (
	OPERATION_ADD    = 0
	OPERATION_MODIFY = 1
	MAX_PROG_REUSE   = 25
	ALU_OPERATION    = 0
	JMP_OPERATION    = 1
	MEM_OPERATION    = 2
)

// Factory method to create a new coverage based strategy.
func NewCoverageBasedStrategy() *CoverageBased {

	// The default program simply initializes the registers to a random
	// value as well as all stack locations from -8 to -512.
	defaultProg, _ := InstructionSequence(
		// Need to patch the fd on every run of prog generation.
		LdMapByFd(R1, 0),
		StW(R10, 0, -4),
		Mov64(R2, R10),
		Add64(R2, -4),
		Call(MapLookup),
		JmpNE(R0, 0, 1),
		Exit(),
		LdDW(R0, R0, 0),
		Mov64(R1, int(rand.SharedRNG.RandInt())),
		Mov64(R2, int(rand.SharedRNG.RandInt())),
		Mov64(R3, int(rand.SharedRNG.RandInt())),
		Mov64(R4, int(rand.SharedRNG.RandInt())),
		Mov64(R5, int(rand.SharedRNG.RandInt())),
		Mov64(R6, int(rand.SharedRNG.RandInt())),
		Mov64(R7, int(rand.SharedRNG.RandInt())),
		Mov64(R8, int(rand.SharedRNG.RandInt())),
		Mov64(R9, int(rand.SharedRNG.RandInt())),
	)
	for i := 16; i <= 512; i += 8 {
		defaultProg = append(defaultProg, StDW(R10, R0, int16(i*-1)))
	}
	return &CoverageBased{
		isFinished:           false,
		pq:                   NewPriorityQueue(),
		coverageHashTable:    make(map[uint64]bool),
		fingerprintHashTable: make(map[uint64]bool),
		programCount:         0,
		validProgramCount:    0,
		mapFd:                -1,
		defaultProg:          defaultProg,
	}
}

// CoverageBased is a strategy that seeks to maximize the number of verifier
// lines of code covered.
// Note that for this strategy to work properly you need to run buzzer with
// the flag `-metricsThreshold=1`.
type CoverageBased struct {
	isFinished           bool
	pq                   *PriorityQueue
	coverageHashTable    map[uint64]bool
	fingerprintHashTable map[uint64]bool
	programCount         int
	validProgramCount    int
	lastProgram          []*epb.Instruction
	mapFd                int
	defaultProg          []*epb.Instruction
}

func mapPtrArithmeticFooter(randomReg epb.Reg, mapFd int) ([]*epb.Instruction, error) {
	return InstructionSequence(
		// Select a random register and store its value in R8.
		Mov64(R8, randomReg),

		// Load a fd to the map.
		LdMapByFd(R9, mapFd),

		StW(R10, 0, -4),
		Mov64(R2, R10),
		Add64(R2, -4),
		Mov64(R1, R9),
		Call(MapLookup),
		JmpNE(R0, 0, 1),
		Exit(),

		// Do ptr arithmetic with the register.
		Add64(R0, R8),
		StDW(R0, 0xCAFE, 0),

		// Exit
		Mov64(R0, 0),
		Exit(),
	)
}

// Returns a deep copy of the program.
func duplicateProgram(prog []*epb.Instruction) []*epb.Instruction {
	ret := []*epb.Instruction{}
	for _, ins := range prog {
		insCp := protobuf.Clone(ins).(*epb.Instruction)
		ret = append(ret, insCp)
	}
	return ret
}

func newRandomInstruction(maxJmp uint64) *epb.Instruction {
	instructionType := rand.SharedRNG.RandInt() % 3
	switch instructionType {
	case ALU_OPERATION:
		return RandomAluInstruction()
	case JMP_OPERATION:
		if maxJmp == 0 {
			return RandomAluInstruction()
		}
		return RandomJmpInstruction(maxJmp)
	case MEM_OPERATION:
		return RandomMemInstruction()
	default:
		return RandomAluInstruction()
	}
}

func handleAddInstruction(prog []*epb.Instruction) ([]*epb.Instruction, error) {
	pos := uint64(rand.SharedRNG.RandInt()) % uint64(len(prog)+1)
	var maxJmp uint64
	if pos == 0 {
		if len(prog) > 0 {
			maxJmp = uint64(len(prog) - 1)
		} else {
			maxJmp = 0
		}
		newInstr := newRandomInstruction(maxJmp)
		return append([]*epb.Instruction{newInstr}, prog...), nil
	} else if pos == uint64(len(prog)) {
		newInstr := newRandomInstruction(0)
		return append(prog, newInstr), nil
	} else {
		if len(prog) > 0 {
			maxJmp = uint64(uint64(len(prog)) - pos - 1)
		} else {
			maxJmp = 0
		}
		newInstr := newRandomInstruction(maxJmp)
		newProg := append(prog[:pos], newInstr)
		return append(newProg, prog[pos:]...), nil
	}
}

func handleModifyInstruction(prog []*epb.Instruction) ([]*epb.Instruction, error) {
	if len(prog) == 0 {
		return handleAddInstruction(prog)
	}
	pos := uint64(rand.SharedRNG.RandInt()) % uint64(len(prog))
	maxJmp := uint64(uint64(len(prog)) - pos - 1)
	newInstr := newRandomInstruction(maxJmp)
	prog[pos] = newInstr
	return prog, nil
}

func mutateProgram(prog []*epb.Instruction, headSize int) ([]*epb.Instruction, error) {
	progHead := prog[:headSize]
	progBody := prog[headSize:]
	operation := rand.SharedRNG.RandInt() % 2
	var err error = nil
	switch operation {
	case OPERATION_ADD:
		progBody, err = handleAddInstruction(progBody)
	case OPERATION_MODIFY:
		progBody, err = handleModifyInstruction(progBody)
	default:
		return nil, unknownOperation
	}
	if err != nil {
		return nil, err
	}
	return append(progHead, progBody...), nil
}

// GenerateProgram should return the instructions to feed the verifier.
func (cv *CoverageBased) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {
	fmt.Printf("Program count: %d, Valid Programs: %d, Queue len: %d\t\t\r", cv.programCount, cv.validProgramCount, cv.pq.Len())
	cv.programCount = cv.programCount + 1

	// If there are no programs in the queue, reuse the default program.
	var progHead []*epb.Instruction
	if cv.pq.IsEmpty() {
		progHead = duplicateProgram(cv.defaultProg)
	} else {
		cvTrace := cv.pq.Pop()
		progHead = duplicateProgram(cvTrace.Program)
		if cvTrace.UsageCount < MAX_PROG_REUSE {
			cvTrace.UsageCount += 1
			cv.pq.Push(cvTrace)
		}
	}

	mutatedProgram, err := mutateProgram(progHead, len(cv.defaultProg))
	cv.lastProgram = mutatedProgram
	if err != nil {
		return nil, err
	}

	// For the footer, write a control and test value to a map, control will
	// not do ptr arithmetic, test will attempt to do some and see if the
	// verifier thinks its safe. We will validate this assumption in onExecuteDone.
	ffi.CloseFD(cv.mapFd)
	cv.mapFd = ffi.CreateMapArray(1)
	if cv.mapFd < 0 {
		return nil, mapCreationFailed
	}

	mutatedProgram[0].Immediate = int32(cv.mapFd)

	footer, err := mapPtrArithmeticFooter(RandomRegister(), cv.mapFd)
	if err != nil {
		return nil, err
	}
	prog := &pb.Program{
		Program: &pb.Program_Ebpf{
			Ebpf: &epb.Program{
				Functions: []*epb.Functions{
					{Instructions: append(mutatedProgram, footer...)},
				},
			},
		},
	}
	return prog, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (cv *CoverageBased) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	// If a program is invalid, ignore it.
	if !verificationResult.IsValid {
		return false
	}
	cv.validProgramCount = cv.validProgramCount + 1

	if !verificationResult.DidCollectCoverage {
		fmt.Printf("Warning: Failed to collect coverage %s\n\t\t\t\t", protobuf.MarshalTextString(verificationResult))
		//cv.isFinished = true
		return false
	}

	// First check if this program introduces any new coverage address
	newAddr := false
	for _, addr := range verificationResult.CoverageAddress {
		if _, ok := cv.coverageHashTable[addr]; !ok {
			newAddr = true

			// Record the new address seen
			cv.coverageHashTable[addr] = true
		}
	}

	// Then calculate the program "coverage fingerprint" and see if it has
	// been observed before
	newFingerPrint := false
	fingerPrint := uint64(0)
	for _, addr := range verificationResult.CoverageAddress {
		fingerPrint ^= addr
	}

	if _, ok := cv.fingerprintHashTable[fingerPrint]; !ok {
		newFingerPrint = true

		// record the new finterprint
		cv.fingerprintHashTable[fingerPrint] = true
	}

	if newAddr || newFingerPrint {
		cv.pq.Push(&CoverageTrace{
			Program:           cv.lastProgram,
			CoverageSignature: fingerPrint,
			CoverageSize:      uint64(len(verificationResult.CoverageAddress)),
			UsageCount:        0,
		})
		fmt.Printf("Pushed new program with signature %02x and coverage size: %d, queue length: %d\t\t\t\t\t\n", fingerPrint, len(verificationResult.CoverageAddress), cv.pq.Len())
		return true
	}

	// If nothing new, don't bother with this program
	return false
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (cv *CoverageBased) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	mapEl, _ := ffi.GetMapElements(cv.mapFd, 1)
	valid := mapEl.Elements[0] == 0xCAFE
	cv.isFinished = !valid
	return valid
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (cv *CoverageBased) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (cv *CoverageBased) IsFuzzingDone() bool {
	return cv.isFinished
}

// Name is used to select the strategy based on a command line flag.
func (cv *CoverageBased) Name() string {
	return "coverage_based"
}
