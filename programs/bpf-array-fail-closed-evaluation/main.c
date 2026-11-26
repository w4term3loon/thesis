#define PROGRAM_NAME "array_reject"
#include "../bpf-runtime.h"

#define KERNEL_ENOTSUPP 524

/* No out-of-bounds access: only a distant cursor excursion and return. */
static struct bpf_insn pointer_roundtrip[] = {
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 4, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_0, 0, 0, 1048576),
    INSN(BPF_ALU64 | BPF_SUB | BPF_K, BPF_REG_0, 0, 0, 1048576),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_0, BPF_REG_0, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
};

/* The final load is reached with element-relative offsets 8 and 16. */
static struct bpf_insn conflicting_join[] = {
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 8, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_0, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_7, BPF_REG_6, 0, 0),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_7, 0, 2, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_6, 0, 0, 8),
    INSN(BPF_JMP | BPF_JA, 0, 0, 1, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_6, 0, 0, 16),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_0, BPF_REG_6, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
};

/* Linux permits pointer spills; the protected profile deliberately does not. */
static struct bpf_insn pointer_spill[] = {
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 3, 0),
    INSN(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_10, BPF_REG_0, -16, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
};

static void say(const char *s)
{
    unsigned long n = 0;
    while (s[n])
        n++;
    syscall3(__NR_write, 1, (long)s, n);
}

static void expect_rejected(struct bpf_insn *insns, unsigned int count,
                            int map_fd, const char *name, const char *message)
{
    static char log[8192];
    union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .prog_flags = BPF_F_TEST_STATE_FREQ,
        .license = (unsigned long)"GPL",
        .log_buf = (unsigned long)log,
        .log_size = sizeof(log),
        .log_level = 1,
    };
    unsigned int i;
    long fd;

    insns[0].imm = map_fd;
    load.insns = (unsigned long)insns;
    load.insn_cnt = count;
    for (i = 0; name[i] && i < BPF_OBJ_NAME_LEN - 1; i++)
        load.prog_name[i] = name[i];
    fd = bpf(BPF_PROG_LOAD, &load);
    if (fd != -KERNEL_ENOTSUPP) {
        if (fd >= 0)
            syscall3(__NR_close, fd, 0, 0);
        say(log);
        fail("FAIL protected profile did not fail closed with ENOTSUPP\n");
    }
    say(message);
}

__attribute__((noreturn)) void _start(void)
{
    union bpf_attr inexact = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = 1048584, /* 1 MiB + 8: an inexact Morello storage extent. */
        .max_entries = 1,
        .map_flags = BPF_F_MMAPABLE,
    };
    int map_fd = create_array_map(BPF_F_MMAPABLE);
    int inexact_fd;

    set_array_value(map_fd, 0, 1);
    expect_rejected(conflicting_join,
                    sizeof(conflicting_join) / sizeof(conflicting_join[0]),
                    map_fd, "eval_join",
                    "PASS conflicting verifier contracts rejected\n");
    expect_rejected(pointer_spill,
                    sizeof(pointer_spill) / sizeof(pointer_spill[0]),
                    map_fd, "eval_spill",
                    "PASS capability-path pointer spill rejected\n");
    expect_rejected(pointer_roundtrip,
                    sizeof(pointer_roundtrip) / sizeof(pointer_roundtrip[0]),
                    map_fd, "eval_roundtrip",
                    "PASS out-of-object pointer roundtrip rejected before execution\n");
    inexact_fd = bpf(BPF_MAP_CREATE, &inexact);
    if (inexact_fd < 0)
        fail("FAIL ordinary ARRAY creation rejected an inexact parent\n");
    /* This version stays at offset zero: only the map geometry is unsupported. */
    pointer_roundtrip[7].imm = 0;
    pointer_roundtrip[8].imm = 0;
    expect_rejected(pointer_roundtrip,
                    sizeof(pointer_roundtrip) / sizeof(pointer_roundtrip[0]),
                    inexact_fd, "eval_map_shape",
                    "PASS ordinary ARRAY creation with inexact parent; protected use rejected\n");
    syscall3(__NR_close, inexact_fd, 0, 0);
    syscall3(__NR_close, map_fd, 0, 0);
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}
