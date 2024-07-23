package strategies

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/units/units"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
	"fmt"
)

func NewPlaygroundStrategy() *Playground {
	return &Playground{isFinished: false}
}

// Playground is a strategy meant for testing, users can generate Arbitrary
// programs and then the results of the verifier will be displayed on screen.
type Playground struct {
	isFinished bool
}

func (pg *Playground) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {

	insn, err := InstructionSequence(
		Mov(R0, 0),
		Exit(),
	)
	if err != nil {
		return nil, err
	}
	prog := &pb.Program{
		Program: &pb.Program_Ebpf{
			Ebpf: &epb.Program{
				Functions: []*epb.Functions{
                    {Instructions: insn, },
				},
			},
		}}
	return prog, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (pg *Playground) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult.VerifierLog)
	pg.isFinished = true
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (pg *Playground) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	return true
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (pg *Playground) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (pg *Playground) IsFuzzingDone() bool {
	return pg.isFinished
}

// StrategyName is used for strategy selection via runtime flags.
func (pg *Playground) Name() string {
	return "playground"
}
