package strategies

import (
	"fmt"
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/units/units"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
)

// StrategyInterface contains all the methods that a fuzzing strategy should
// implement.
type PointerArithmetic struct {
	IsFinished bool
}

// GenerateProgram should return the instructions to feed the verifier.
func (pa *PointerArithmetic) GenerateProgram(ffi *units.FFI) ([]*epb.Instruction, error) {
	return InstructionSequence(
		Mov64(R0, 0),
		Exit(),
	)
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (pa *PointerArithmetic) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult.VerifierLog)
	pa.IsFinished = true
	return false
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (pa *PointerArithmetic) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	return true
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (pa *PointerArithmetic) OnError(e error) bool {
	return true
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (pa *PointerArithmetic) IsFuzzingDone() bool {
	return pa.IsFinished
}
