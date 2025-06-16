// Copyright 2024 Google LLC
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

package cbpf

import pb "buzzer/proto/cbpf_go_proto"

type Src interface {
	pb.Reg | int32 | int
}

const (
	// Constants related to the encoding of cbpf operations
	// UnusedField Unused Field.
	UnusedField = 0x00
)
const (
	A = pb.Reg_A
	X = pb.Reg_X
)

// classic BPF instruction structure
// https://www.infradead.org/~mchehab/kernel_docs/networking/filter.html#structure
type Filter struct {
	Opcode uint16
	Jt     uint8
	Jf     uint8
	K      uint32
}

// https://elixir.bootlin.com/linux/v6.10/source/include/uapi/linux/filter.h#L65
const (
	ExtensionOffset = -0x1000
)
