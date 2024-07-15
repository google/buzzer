package strategies

import (
	. "buzzer/pkg/cbpf/cbpf"
	"buzzer/pkg/units/units"
	cpb "buzzer/proto/cbpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
	"fmt"
)

func NewCbpfPlaygroundStrategy() *Cbpf_Playground {
	return &Cbpf_Playground{isFinished: false}
}

type Cbpf_Playground struct {
	isFinished bool
}

func CbpfInstructionSequence(instructions ...*cpb.Instruction) ([]*cpb.Instruction, error) {
	for index, inst := range instructions {
		if inst == nil {
			return nil, fmt.Errorf("Nil instruction at index %d, did you pass an unsigned int value?", index)
		}
	}
	return instructions, nil
}

func (pg *Cbpf_Playground) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {
	insn, err := CbpfInstructionSequence(
		Add(int32(1)),
		Ret(int32(0)),
	)
	if err != nil {
		return nil, err
	}
	prog := &pb.Program{}
	prog.Program = &pb.Program_Cbpf{
		Cbpf: &cpb.Program{Instructions: insn},
	}
	return prog, nil
}

func (pg *Cbpf_Playground) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult)
	pg.isFinished = true
	return true
}

func (pg *Cbpf_Playground) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	return true
}

func (pg *Cbpf_Playground) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

func (pg *Cbpf_Playground) IsFuzzingDone() bool {
	return pg.isFinished
}

func (pg *Cbpf_Playground) Name() string {
	return "cbpf_playground"
}
