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
	PseudoMapFD = pb.Reg_R1
)

const (
	// ebpf helper function codes
	// MapLookup Map Lookup helper function.
	MapLookup            = 0x01
	SkbLoadBytesRelative = 0x44
)
