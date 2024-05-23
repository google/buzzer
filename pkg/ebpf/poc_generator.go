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

import (
	pb "buzzer/proto/ebpf_go_proto"
	jsonpb "github.com/golang/protobuf/jsonpb"
	"errors"
	"fmt"
	"os"
)


// GeneratePoc generates a c program that can be used to reproduce fuzzer
// test cases.
func GeneratePoc(program *pb.Program) error {
	m := &jsonpb.Marshaler{
		OrigName: true,
		EnumsAsInts: false,
		EmitDefaults: true,
		Indent: "   ",
	}
	textpbData, err := m.MarshalToString(program)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "ebpf-poc-*.json")
	if err != nil {
		return err
	}

	fmt.Printf("Writing eBPF PoC %q.\n", f.Name())
	_, err = f.Write([]byte(textpbData))
	return errors.Join(err, f.Close())

}
