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

package ebpf

import (
	pb "buzzer/proto/btf_go_proto"
	"bytes"
	"encoding/binary"
	"fmt"
	proto "github.com/golang/protobuf/proto"
)

// SetHeaderSection takes a BTF proto and assigns the header values, magic
// represents if the system is big or little endian (0xeb9f, 0x9feb).
func SetHeaderSection(btf *pb.Btf, magic int32, version int32, flags int32) {
	btf.Header = &pb.Header{
		Magic:   magic,
		Version: version,
		Flags:   flags,
		HdrLen:  0x18,
		TypeOff: 0x0,
		TypeLen: int32(proto.Size(btf.TypeSection)),
		StrOff:  int32(proto.Size(btf.TypeSection)),
		StrLen:  int32(proto.Size(btf.StringSection)),
	}
}

// SetTypeSection populates the BTF type section of the provided BTF proto with
// the parameter types
func SetTypeSection(btf *pb.Btf, types []*pb.BtfType) {
	btf.TypeSection = &pb.TypeSection{
		BtfType: types,
	}
}

// SetTypeInfo returns the parameter type info encoded,
// the bits arrangement is:
//   - bits 0-15  = vlen
//   - bits 16-23 = unused
//   - bits 24-28 = kind
//   - bits 29-30 = unused
//   - bits    31 = kind_flag
//
// https://docs.kernel.org/bpf/btf.html#:~:text=Each%20type%20contains%20the%20following%20common%20data%3A
func SetTypeInfo(vlen int16, kind pb.BtfKind, kind_flag bool) int32 {
	info := int32(0)
	info |= int32(vlen)
	info |= int32(kind) << 24
	flag := 0
	if kind_flag {
		flag = 1
	}
	info |= int32(flag) << 28
	return info
}

// SetStringSection populates the BTF string section of the provided BTF proto
// with the parameter string
func SetStringSection(btf *pb.Btf, str string) {
	btf.StringSection = &pb.StringSection{
		Str: str,
	}
}

// GetBuffer takes a BTF Proto and returns its serialized value as a byte array.
func GetBuffer(btf *pb.Btf) []byte {
	buffer, err := generateBtf(btf)
	if err != nil {
		fmt.Println(err)
	}
	return buffer
}

func generateBtf(btf_proto *pb.Btf) ([]byte, error) {
	var btf_buff bytes.Buffer
	var err error

	var type_data = []any{}
	for _, t := range btf_proto.TypeSection.BtfType {
		type_data = append(type_data, t.NameOff)
		type_data = append(type_data, t.Info)
		type_data = append(type_data, t.SizeOrType)
		switch e := t.Extra.(type) {
		case *pb.BtfType_IntTypeData:
			type_data = append(type_data, e.IntTypeData.IntInfo)
		case *pb.BtfType_StructTypeData:
			type_data = append(type_data, e.StructTypeData.NameOff)
			type_data = append(type_data, e.StructTypeData.StructType)
			type_data = append(type_data, e.StructTypeData.Offset)
		case *pb.BtfType_FuncProtoTypeData:
			for _, param := range e.FuncProtoTypeData.Param {
				type_data = append(type_data, param.NameOff)
				type_data = append(type_data, param.ParamType)
			}
		}
	}
	var types_buff bytes.Buffer
	for _, types := range type_data {
		err = binary.Write(&types_buff, binary.LittleEndian, types)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
	}

	string_data := []byte(btf_proto.StringSection.Str)
	var string_buff bytes.Buffer
	// The first string in the string section must be a null string
	string_buff.Write([]byte{0})
	for _, strings := range string_data {
		err = binary.Write(&string_buff, binary.LittleEndian, strings)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
		string_buff.Write([]byte{0})
	}

	btf_proto.Header.TypeLen = int32(len(types_buff.Bytes()))
	btf_proto.Header.StrOff = int32(len(types_buff.Bytes()))
	btf_proto.Header.StrLen = int32(len(string_buff.Bytes()))

	var header_data = []any{
		uint16(btf_proto.Header.Magic),
		uint8(btf_proto.Header.Version),
		uint8(btf_proto.Header.Flags),
		btf_proto.Header.HdrLen,
		btf_proto.Header.TypeOff,
		btf_proto.Header.TypeLen,
		btf_proto.Header.StrOff,
		btf_proto.Header.StrLen,
	}
	for _, header := range header_data {
		err = binary.Write(&btf_buff, binary.LittleEndian, header)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
	}

	btf_buff.Write(types_buff.Bytes())
	btf_buff.Write(string_buff.Bytes())
	return btf_buff.Bytes(), nil
}
