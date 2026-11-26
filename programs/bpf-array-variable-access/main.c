#define PROGRAM_NAME "array_var"
#include "../bpf-runtime.h"

/* Read and write one value through bounded variable ADD and SUB cursors. */
static struct bpf_insn program[] = {
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
    INSN(BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, BPF_REG_0, -4, 0),
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 18, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_6, BPF_REG_1, 0, 0),
    INSN(BPF_JMP | BPF_JGT | BPF_K, BPF_REG_6, 0, 14, 1),
    INSN(BPF_ALU64 | BPF_LSH | BPF_K, BPF_REG_6, 0, 0, 3),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_1, BPF_REG_6, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_0, BPF_REG_1, 8, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_7, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_3, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_3, 0, 0, 8),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_2, BPF_REG_3, 0, 0),
    INSN(BPF_ALU64 | BPF_SUB | BPF_X, BPF_REG_2, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_3, BPF_REG_0, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_3, 0, 0, 1),
    INSN(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_2, BPF_REG_3, 8, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_3, BPF_REG_2, 8, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_3, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
};

__attribute__((noreturn)) void _start(void)
{
    static __u32 key;
    static __u64 value[4] = { 1, 0, 42, 0 };
    union bpf_attr update;
    int fd = create_array_map(BPF_F_MMAPABLE);

    update = (union bpf_attr) { .map_fd = fd,
                                .key = (unsigned long)&key,
                                .value = (unsigned long)value };
    if (bpf(BPF_MAP_UPDATE_ELEM, &update) < 0)
        fail("BPF_MAP_UPDATE_ELEM failed\n");
    program[2].imm = fd;
    run_bpf(program, sizeof(program) / sizeof(program[0]), 85);
}
