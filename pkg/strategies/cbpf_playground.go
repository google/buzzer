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

func (pg *Cbpf_Playground) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {
	insn := []*cpb.Instruction{
		Add(1), Ret(0)}
	prog := &pb.Program{
		Program: &pb.Program_Cbpf{
			Cbpf: &cpb.Program{Instructions: insn},
		},
	}
	return prog, nil
}

func (pg *Cbpf_Playground) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	fmt.Println(verificationResult)
	pg.isFinished = true
	return true
}

func (pg *Cbpf_Playground) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	fmt.Println(executionResult)
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
