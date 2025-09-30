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

import pb "buzzer/proto/ebpf_go_proto"

const (
	// Constants related to the encoding of ebpf operations
	// UnusedField Unused Field.
	UnusedField = 0x00
)

const (
	PseudoMapFD  = pb.Reg_R1
	PseudoMapIdx = pb.Reg_R5
)

const (
	R0  = pb.Reg_R0
	R1  = pb.Reg_R1
	R2  = pb.Reg_R2
	R3  = pb.Reg_R3
	R4  = pb.Reg_R4
	R5  = pb.Reg_R5
	R6  = pb.Reg_R6
	R7  = pb.Reg_R7
	R8  = pb.Reg_R8
	R9  = pb.Reg_R9
	R10 = pb.Reg_R10
)

const (
	// ebpf helper function codes
	// MapLookup Map Lookup helper function.
	MapLookup            = 0x01
	SkbLoadBytesRelative = 0x44
)
