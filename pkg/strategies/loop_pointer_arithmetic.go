package strategies

import (
	. "buzzer/pkg/ebpf/ebpf"
	"buzzer/pkg/rand"
	"buzzer/pkg/units/units"
	btfpb "buzzer/proto/btf_go_proto"
	epb "buzzer/proto/ebpf_go_proto"
	fpb "buzzer/proto/ffi_go_proto"
	pb "buzzer/proto/program_go_proto"
	"fmt"
)

func NewLoopPointerArithmeticStrategy() *LoopPointerArithmetic {
	return &LoopPointerArithmetic{isFinished: false}
}

// LoopPointerArithmetic is a strategy meant for testing, users can generate Arbitrary
// programs and then the results of the verifier will be displayed on screen.
type LoopPointerArithmetic struct {
	isFinished        bool
	mapFd             int
	programCount      int
	validProgramCount int
	log               string
}

func types() []*btfpb.BtfType {
	types := []*btfpb.BtfType{}

	// 1: Func_Proto
	types = append(types, &btfpb.BtfType{
		NameOff:    0x0,
		Info:       SetTypeInfo(0, btfpb.BtfKind_FUNCPROTO, false),
		SizeOrType: 0x0,
		Extra: &btfpb.BtfType_Empty{
			Empty: &btfpb.Empty{},
		},
	})

	// 2: Func
	types = append(types, &btfpb.BtfType{
		NameOff:    0x1,
		Info:       SetTypeInfo(0, btfpb.BtfKind_FUNC, false),
		SizeOrType: 0x01,
		Extra: &btfpb.BtfType_Empty{
			Empty: &btfpb.Empty{},
		},
	})

	// 3: Int
	types = append(types, &btfpb.BtfType{
		NameOff:    0x1,
		Info:       SetTypeInfo(0, btfpb.BtfKind_INT, false),
		SizeOrType: 0x4,
		Extra: &btfpb.BtfType_IntTypeData{
			IntTypeData: &btfpb.IntTypeData{IntInfo: 0x01000020},
		},
	})

	// 4: Struct
	types = append(types, &btfpb.BtfType{
		NameOff:    0x1,
		Info:       SetTypeInfo(1, btfpb.BtfKind_STRUCT, false),
		SizeOrType: 0x4,
		Extra: &btfpb.BtfType_StructTypeData{
			StructTypeData: &btfpb.StructTypeData{
				NameOff:    0x1,
				StructType: 0x3,
				Offset:     0x0,
			},
		},
	})

	// 5: Ptr
	types = append(types, &btfpb.BtfType{
		NameOff:    0x0,
		Info:       SetTypeInfo(0, btfpb.BtfKind_PTR, false),
		SizeOrType: 0x4,
		Extra: &btfpb.BtfType_Empty{
			Empty: &btfpb.Empty{},
		},
	})

	// 6: Func_Proto
	types = append(types, &btfpb.BtfType{
		NameOff:    0x0,
		Info:       SetTypeInfo(2, btfpb.BtfKind_FUNCPROTO, false),
		SizeOrType: 0x3,
		Extra: &btfpb.BtfType_FuncProtoTypeData{
			FuncProtoTypeData: &btfpb.FuncProtoTypeData{
				Param: []*btfpb.BtfParam{
					{NameOff: 0x1, ParamType: 0x3},
					{NameOff: 0x1, ParamType: 0x5},
				},
			},
		},
	})

	// 7: Func
	types = append(types, &btfpb.BtfType{
		NameOff:    0x1,
		Info:       SetTypeInfo(0, btfpb.BtfKind_FUNC, false),
		SizeOrType: 0x6,
		Extra: &btfpb.BtfType_Empty{
			Empty: &btfpb.Empty{},
		},
	})
	return types
}

func (lp *LoopPointerArithmetic) GenerateProgram(ffi *units.FFI) (*pb.Program, error) {
	lp.programCount += 1
	fmt.Printf("Generated %d programs, %d were valid               \r", lp.programCount, lp.validProgramCount)

	// Setup BTF Section
	btf := &btfpb.Btf{}
	SetHeaderSection(btf, 0xeb9f, 0x01, 0x0)
	SetTypeSection(btf, types())
	SetStringSection(btf, "buzzer")

	mapFd := ffi.CreateMapArray(2)
	ffi.CloseFD(lp.mapFd)
	lp.mapFd = mapFd

	mainBody, _ := InstructionSequence(
		// Load a fd to the map.
		LdMapByFd(R9, mapFd), // R9 = Map File Descriptor
		// Begin by writing a value to the map without ptr arithmetic.
		StW(R10, 0, -4), // R10[-4] = 0
		Mov64(R2, R10),  // R2 = R10
		Add64(R2, -4),   // R2 = R10[-4] = 0 (param 2)
		Mov64(R1, R9),   // R1 = R9 (mapf fd) (param 1)
		Call(MapLookup), // if map != succes: exit() // *R0 = map[0]
		JmpNE(R0, 0, 1),
		Exit(),
		StDW(R0, 0xCAFE, 0), // R0[0] = 0xCAFE

		// Now repeat the operation but doing pointer arithmetic.
		StW(R10, 1, -4), // R10[-4] = 1
		Mov64(R2, R10),  // R2 = R10
		Add64(R2, -4),   // R2 = R10[-4] = 1  (param 2)
		Mov64(R1, R9),   // R1 = R9 (map fd) (param 1)
		Call(MapLookup), // if map != success: exit
		JmpNE(R0, 0, 1),
		Exit(),

		LdW(R8, R10, -12), // R8 = 3
		Add64(R0, R8),     // *R0 = map[1] => *R0 += 3
		StW(R0, R8, 0),    // R0[0] = R8

		Mov64(R0, 0),
		Exit(), // return 0
	)

	mainHeader, _ := InstructionSequence(
		// Set up and call loop function
		StW(R10, 0, -4),                       // Stack[-4] = 0
		StW(R10, 0, -12),                      // Stack[-12] = 0
		Mov64(R3, R10),                        // R3 = stack
		Add64(R3, -8),                         // R3 = stack[-8] (param 3, *ctx)
		Mov(R1, 10),                           // R1 = 10 (param 1, # iterations)
		Mov(R4, 0),                            // R4 = 0 (param 4, flags)
		LdFunctionPtr(int32(len(mainBody)+3)), // R2 = func (param 2)
		Call(181),                             // Call loop
	)
	main := append(mainHeader, mainBody...)

	loopFuncHead, _ := InstructionSequence(
		StDW(R10, R2, -8),
	)

	instructionCount := rand.SharedRNG.RandInt() % 1000
	loopFuncBody, _ := InstructionSequence(
		Mov64(R0, int32(rand.SharedRNG.RandInt())),
		Mov64(R2, int32(rand.SharedRNG.RandInt())),
		Mov64(R3, int32(rand.SharedRNG.RandInt())),
		Mov64(R4, int32(rand.SharedRNG.RandInt())),
		Mov64(R5, int32(rand.SharedRNG.RandInt())),
		Mov64(R6, int32(rand.SharedRNG.RandInt())),
		Mov64(R7, int32(rand.SharedRNG.RandInt())),
		Mov64(R8, int32(rand.SharedRNG.RandInt())),
		Mov64(R9, int32(rand.SharedRNG.RandInt())),
	)
	for instructionCount != 0 {
		instructionCount -= 1
		var instruction *epb.Instruction
		t := rand.SharedRNG.RandInt() % 4
		randReg := RandomRegister()
		for randReg == 2 || randReg == 1 {
			randReg = RandomRegister()
		}
		switch t {
		case 0:
			instructions, _ := InstructionSequence(
				LdDW(R2, R10, -8),
				And(randReg, 0x3f),
				Mul64(randReg, -1),
				Add64(R2, randReg),
				StB(R2, 16, 0),
				Mov64(R2, int32(rand.SharedRNG.RandInt())),
			)
			loopFuncBody = append(loopFuncBody, instructions...)
		case 1:
			instruction = RandomLoadInstruction()

			loopFuncBody = append(loopFuncBody, instruction)
		default:
			if rand.SharedRNG.RandRange(1, 100) > 30 || instructionCount == 0 {
				instruction = RandomAluInstruction()
			} else {

				instruction = RandomJmpInstruction(uint64(instructionCount))
			}

			loopFuncBody = append(loopFuncBody, instruction)
		}
	}

	loopFuncFoo, _ := InstructionSequence(
		Mov(R0, 0),
		Exit(),
	)

	loopFunc := append(loopFuncHead, loopFuncBody...)
	loopFunc = append(loopFunc, loopFuncFoo...)

	func_info_na := &btfpb.FuncInfo{InsnOff: 0, TypeId: int32(btfpb.TypeId_NA)}
	func_info_loop := &btfpb.FuncInfo{InsnOff: int32(len(main) + 2), TypeId: int32(btfpb.TypeId_FUNC_PTR_INT)}
	prog := &pb.Program{
		Program: &pb.Program_Ebpf{
			Ebpf: &epb.Program{
				Functions: []*epb.Functions{
					{Instructions: main, FuncInfo: func_info_na},
					{Instructions: loopFunc, FuncInfo: func_info_loop},
				},
				Btf: GetBuffer(btf),
			},
		},
	}
	return prog, nil
}

// OnVerifyDone process the results from the verifier. Here the strategy
// can also tell the fuzzer to continue with execution by returning true
// or start over and generate a new program by returning false.
func (lp *LoopPointerArithmetic) OnVerifyDone(ffi *units.FFI, verificationResult *fpb.ValidationResult) bool {
	if verificationResult.IsValid {
		lp.validProgramCount += 1
	}
	lp.log = verificationResult.VerifierLog
	return true
}

// OnExecuteDone should validate if the program behaved like the
// verifier expected, if that was not the case it should return false.
func (lp *LoopPointerArithmetic) OnExecuteDone(ffi *units.FFI, executionResult *fpb.ExecutionResult) bool {
	mapElements, err := ffi.GetMapElements(lp.mapFd, 2)
	if err != nil {
		fmt.Println(err)
		return true
	}
	if mapElements.Elements[1] != 0 {
		fmt.Println(mapElements)
		fmt.Println(executionResult)
		fmt.Println(lp.log)
	}
	return mapElements.Elements[1] == 0
}

// OnError is used to determine if the fuzzer should continue on errors.
// true represents continue, false represents halt.
func (lp *LoopPointerArithmetic) OnError(e error) bool {
	fmt.Printf("error %v\n", e)
	return false
}

// IsFuzzingDone if true, buzzer will break out of the main fuzzing loop
// and return normally.
func (lp *LoopPointerArithmetic) IsFuzzingDone() bool {
	return lp.isFinished
}

// StrategyName is used for strategy selection via runtime flags.
func (lp *LoopPointerArithmetic) Name() string {
	return "loop_pointer_arithmetic"
}
