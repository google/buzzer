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
	"errors"
	"fmt"
	"os"
)

const (
	aluImmMacroDef = `
#define BPF_ALU_IMM(OP, DST, IMM, INS_CLASS)				\
	((struct bpf_insn) {					\
		.code  = INS_CLASS | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
`
	aluRegMacroDef = `
#define BPF_ALU_REG(OP, DST, SRC, INS_CLASS)				\
	((struct bpf_insn) {					\
		.code  = INS_CLASS | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
`
	exitMacroDef = `
#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })
	`
	jumpImmMacroDef = `
#define BPF_JMP_IMM(OP, DST, IMM, OFF, INS_CLASS)				\
	((struct bpf_insn) {					\
		.code  = INS_CLASS | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })
`
	jumpRegMacroDef = `
#define BPF_JMP_REG(OP, DST, SRC, OFF, INS_CLASS)				\
	((struct bpf_insn) {					\
		.code  = INS_CLASS | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
`
	callMacroDef = `
#define BPF_CALL_FUNC(FUNCTION_NUMBER)						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = FUNCTION_NUMBER })
`
	loadMapFdDef = `
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = 0x01,					\
		.off   = 0,					\
		.imm   = (__u32) (MAP_FD) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (MAP_FD)) >> 32 })
`
	memOperationMacroDef = `
#define BPF_MEM_OPERATION(INS_CLASS, SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = INS_CLASS | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
`
)

const (
	cHeader = `#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
`
	progLoadFunc = `
// loads a prog and returns the FD
int load_prog(void *prog_buff, size_t size) {
  struct bpf_insn *insn;
  union bpf_attr attr = {};

  // For the verifier log.
  int log_size = 100000;
  unsigned char log_buf[log_size];
  memset(log_buf, 0, log_size);

  insn = (struct bpf_insn *)prog_buff;
  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.insns = (uint64_t)insn;
  attr.insn_cnt = (size * sizeof(uint64_t)) / (sizeof(struct bpf_insn));
  attr.license = (uint64_t) "GPL";
  attr.log_size = sizeof(log_buf);
  attr.log_buf = (uint64_t)log_buf;
  attr.log_level = 3;

  int program_fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

  if (program_fd < 0) {
    // Return why we failed to load the program.
    for(int i = 0; i < log_size; i++) {
	    printf("%c", log_buf[i]);
    }
    printf("Could not load program: %s\n", strerror(errno));
    return -1;
  }

  return program_fd;
}
`
	createMapFunc = `
int bpf_create_map(unsigned int max_entries) {
  union bpf_attr attr = {.map_type = BPF_MAP_TYPE_ARRAY,
                         .key_size = sizeof(uint32_t),
                         .value_size = sizeof(uint64_t),
                         .max_entries = max_entries};

  return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}
`
	executeProgramFunc = `
static int setup_send_sock() {
  return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
}

static int setup_listener_sock() {
  int sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (sock_fd < 0) {
    return sock_fd;
  }

  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(1337);
  serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

  int err = bind(sock_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
  if (err < 0) return err;

  err = listen(sock_fd, 32);
  if (err < 0) return err;

  return sock_fd;
}

int execute_bpf_program(int prog_fd, int map_fd, int map_count, uint64_t* map_contents) {
  int listener_sock = setup_listener_sock();
  int send_sock = setup_send_sock();

  if (listener_sock < 0 || send_sock < 0) {
    printf("Could not open sockets\n");
    return -1;
  }

  if (setsockopt(listener_sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
                 sizeof(prog_fd)) < 0) {
    printf("Could not attach bpf program to socket\n");
    return -1;
  }

  // trigger execution by connecting to the listener socket
  struct sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(1337);
  serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

  // no need to check connect, it will fail anyways
  connect(send_sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

  close(listener_sock);
  close(send_sock);
  for (uint64_t key = 0; key < map_count; key++) {
    uint64_t element = 0;
    union bpf_attr lookup_map = {.map_fd = (uint32_t)map_fd,
                                 .key = (uint64_t)&key,
                                 .value = (uint64_t)&element};
    int err =
        syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map));
    if (err < 0) {
      printf("could not lookup map element %ul\n", key);
      return -1;
    }
    map_contents[key] = element;
  }
  return 0;
}

`
)

// GeneratePoc generates a c program that can be used to reproduce fuzzer
// test cases.
func GeneratePoc(prog *Program) error {
	macros := prog.root.GeneratePoc()
	pocString := ""
	for i, m := range macros {
		if i != len(macros)-1 {
			pocString += fmt.Sprintf("\t\t\t%s,\n", m)
		} else {
			pocString += fmt.Sprintf("\t\t\t%s\n", m)
		}
	}
	mainBody := fmt.Sprintf(`int main() {
		int map_size = %d;
		int map_fd = bpf_create_map(map_size);
		uint64_t map_contents[map_size];
		memset(map_contents, 0, sizeof(map_contents));
		if (map_fd < 0) {
			printf("Could not create map\n");
			return -1;
		}
		struct bpf_insn instrs[] = {
%s
		};
		int prog_fd = load_prog(instrs, /*prog_len=*/sizeof(instrs)/sizeof(instrs[0]));
		if ( prog_fd < 0) {
			printf("Could not load program\n");
			return -1;
		}
		printf("program loaded successully\n");

		int did_succeed = 0;
		if (execute_bpf_program(prog_fd, map_fd, map_size, map_contents) < 0) {
			return -1;
		}
		for (int i = 0; i < map_size; i++) {
			printf("map_element %%llu: %%llu\n", i, map_contents[i]);
		}

		return 0;
}`, prog.MapSize, pocString)

	poc := cHeader + aluImmMacroDef + aluRegMacroDef + exitMacroDef + jumpRegMacroDef + jumpImmMacroDef + callMacroDef + loadMapFdDef + memOperationMacroDef + progLoadFunc + createMapFunc + executeProgramFunc + mainBody
	f, err := os.CreateTemp("", "ebpf-poc-*.c")
	if err != nil {
		return err
	}

	fmt.Printf("Writing eBPF PoC %q.\n", f.Name())
	_, err = f.Write([]byte(poc))
	return errors.Join(err, f.Close())

}
