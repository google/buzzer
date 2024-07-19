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
		Magic:   0x9feb,
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
	btf := Btf()
	buf := new(bytes.Buffer)

	var data = []any{

		uint16(btf.Header.Magic),
		uint8(btf.Header.Version),
		uint8(btf.Header.Flags),
		btf.Header.HdrLen,
		btf.Header.TypeOff,
		btf.Header.TypeLen,
		btf.Header.StrOff,
		btf.Header.StrLen,
	}
	for _, t := range btf.TypeSection.BtfType {
		data = append(data, t.NameOff)
		data = append(data, t.Info)
		switch e := t.Extra.(type) {
		case *pb.BtfType_IntTypeData:
			data = append(data, e.IntTypeData.IntInfo)
		case *pb.BtfType_StructTypeData:
			data = append(data, e.StructTypeData.NameOff)
			data = append(data, e.StructTypeData.StructType)
			data = append(data, e.StructTypeData.Offset)
		case *pb.BtfType_FuncProtoTypeData:
			for _, param := range e.FuncProtoTypeData.Param {
				data = append(data, param.NameOff)
				data = append(data, param.ParamType)
			}
		}
	}

	data = append(data, []byte(btf.StringSection.Str))

	for _, v := range data {
		err := binary.Write(buf, binary.LittleEndian, v)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
			return nil, err
		}
	}

	return buf.Bytes(), nil

}
