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

func typeSection() *pb.TypeSection {

	types := []*pb.BtfType{}

	// 1: Func_Proto
	types = append(types, &pb.BtfType{
		NameOff:    0x0,
		Info:       0x0d000000,
		SizeOrType: 0x0,
		Extra: &pb.BtfType_Empty{
			Empty: &pb.Empty{},
		},
	})

	// 2: Func
	types = append(types, &pb.BtfType{
		NameOff:    0x1,
		Info:       0x0c000000,
		SizeOrType: 0x01,
		Extra: &pb.BtfType_Empty{
			Empty: &pb.Empty{},
		},
	})

	// 3: Int
	types = append(types, &pb.BtfType{
		NameOff:    0x1,
		Info:       0x01000000,
		SizeOrType: 0x4,
		Extra: &pb.BtfType_IntTypeData{
			IntTypeData: &pb.IntTypeData{IntInfo: 0x01000020},
		},
	})

	// 4: Struct
	types = append(types, &pb.BtfType{
		NameOff:    0x1,
		Info:       0x04000001,
		SizeOrType: 0x4,
		Extra: &pb.BtfType_StructTypeData{
			StructTypeData: &pb.StructTypeData{
				NameOff:    0x1,
				StructType: 0x3,
				Offset:     0x0,
			},
		},
	})

	// 5: Ptr
	types = append(types, &pb.BtfType{
		NameOff:    0x0,
		Info:       0x02000000,
		SizeOrType: 0x4,
		Extra: &pb.BtfType_Empty{
			Empty: &pb.Empty{},
		},
	})

	// 6: Func_Proto
	types = append(types, &pb.BtfType{
		NameOff:    0x0,
		Info:       0x0d000002,
		SizeOrType: 0x3,
		Extra: &pb.BtfType_FuncProtoTypeData{
			FuncProtoTypeData: &pb.FuncProtoTypeData{
				Param: []*pb.BtfParam{
					{NameOff: 0x1, ParamType: 0x3},
					{NameOff: 0x1, ParamType: 0x5},
				},
			},
		},
	})

	// 7: Func
	types = append(types, &pb.BtfType{
		NameOff:    0x1,
		Info:       0x0c000000,
		SizeOrType: 0x6,
		Extra: &pb.BtfType_Empty{
			Empty: &pb.Empty{},
		},
	})
	return &pb.TypeSection{BtfType: types}
}

func stringSection() *pb.StringSection {
	// For buzzer's BTF Implementation the string sections is not currently
	// in used.
	return &pb.StringSection{Str: "buzzer"}
}

func Btf() *pb.Btf {
	type_section := typeSection()
	string_section := stringSection()
	header := &pb.Header{
		Magic:   0xeb9f,
		Version: 0x01,
		Flags:   0x00,
		HdrLen:  0x18,
		TypeOff: 0x0,
		TypeLen: int32(proto.Size(type_section)),
		StrOff:  int32(proto.Size(type_section)),
		StrLen:  int32(proto.Size(string_section)),
	}
	return &pb.Btf{
		Header:        header,
		TypeSection:   type_section,
		StringSection: string_section,
	}
}

func GetBtf() ([]byte, error) {
	btf_proto := Btf()
	btf_buff := new(bytes.Buffer)
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
	types_buff := new(bytes.Buffer)
	for _, types := range type_data {
		err = binary.Write(types_buff, binary.LittleEndian, types)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
	}

	string_data := []byte(btf_proto.StringSection.Str)
	string_buff := new(bytes.Buffer)
	for _, strings := range string_data {
		err = binary.Write(string_buff, binary.LittleEndian, strings)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
		string_buff.Write([]byte{0})
	}

	btf_proto.Header.TypeLen = int32(len(types_buff.Bytes()))
	btf_proto.Header.StrOff = int32(len(types_buff.Bytes()))
	btf_proto.Header.StrLen = int32(len(string_buff.Bytes()) + 1)

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
		err = binary.Write(btf_buff, binary.LittleEndian, header)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
	}

	btf_buff.Write(types_buff.Bytes())
	// The first string in the string section must be a null string
	btf_buff.Write([]byte{0})
	btf_buff.Write(string_buff.Bytes())
	return btf_buff.Bytes(), nil

}
