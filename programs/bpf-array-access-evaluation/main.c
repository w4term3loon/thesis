#define PROGRAM_NAME "array_eval"
#include "../bpf-runtime.h"

/* Both branches reach r8 = element + 32, then SUB and a negative displacement
 * access element + 16. Only the load/store width and lookup key vary.
 */
static struct bpf_insn program[] = {
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 15, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_0, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_7, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_6, 0, 0),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_7, 0, 3, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 8),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 24),
    INSN(BPF_JMP | BPF_JA, 0, 0, 1, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 32),
    INSN(BPF_ALU64 | BPF_SUB | BPF_K, BPF_REG_8, 0, 0, 8),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_9, BPF_REG_6, 8, 0),
    INSN(BPF_STX | BPF_MEM | BPF_B, BPF_REG_8, BPF_REG_9, -8, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_5, BPF_REG_8, -8, 0),
    INSN(BPF_JMP | BPF_JNE | BPF_X, BPF_REG_5, BPF_REG_9, 2, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 42),
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

static void number(unsigned int n)
{
    char digits[10];
    unsigned int i = sizeof(digits);
    do {
        digits[--i] = '0' + n % 10;
        n /= 10;
    } while (n);
    syscall3(__NR_write, 1, (long)(digits + i), sizeof(digits) - i);
}

static void check_pruned_join(const char *log)
{
    static const char needle[] = "15: safe"; /* Join before SUB and memory use. */
    for (unsigned int i = 0; log[i]; i++) {
        unsigned int n = 0;
        while (needle[n] && log[i + n] == needle[n])
            n++;
        if (!needle[n]) {
            say("PASS verifier pruning: equivalent join at pc=15 before protected accesses\n");
            return;
        }
    }
    say(log);
    fail("FAIL expected equivalent-state pruning at the access join\n");
}

/* Require all four complete access sequences, not just successful output. */
static unsigned int inspect_jit(int fd, unsigned int scale)
{
    static __u32 code[512];
    struct bpf_prog_info info = {};
    union bpf_attr attr = {};
    unsigned int windows = 0, loads = 0, stores = 0, gates = 0;
    unsigned int frames = 0, stack_windows = 0;

    info.jited_prog_len = sizeof(code);
    info.jited_prog_insns = (unsigned long)code;
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0 || !info.jited_prog_len ||
        info.jited_prog_len > sizeof(code))
        fail("FAIL JIT inspection unavailable\n");
    for (unsigned int i = 0; i < info.jited_prog_len / 4; i++) {
        loads += (code[i] & 0xff3ffc00) == 0xe2000400;
        stores += (code[i] & 0xff3ffc00) == 0xe2000000;
        gates += code[i] == 0xc2c232e0;
        frames += code[i] == 0xc2ca2339;
        if (code[i] == 0xc2cc214a) { /* scbndse c10, c10, x12 */
            check_access_direction(code, info.jited_prog_len / 4, i);
            if (i < 5 || i + 7 >= info.jited_prog_len / 4)
                fail("FAIL truncated access window\n");
            unsigned int actual_base = (code[i - 5] >> 5) & 31;
            if (actual_base == 25 || actual_base == 1) {
                stack_windows++; /* Stack key store and generated key read. */
                continue;
            }
            unsigned int base = windows < 2 ? 19 : 21;
            unsigned int off = windows == 0 ? 0 : windows == 1 ? 8 : 16;
            unsigned int s = windows == 0 ? 0 : scale;
            unsigned int value = windows == 0 ? 20 : windows == 3 ? 4 : 22;
            __u32 displacement = windows < 2 ? 0xd280000c | (off << 5) :
                                               0x928000ec; /* mov x12, -8 */
            __u32 memory = 0xe2000140 | (s << 22) | value |
                           (windows == 2 ? 0 : 0x400);

            if (windows >= 4 ||
                code[i - 5] != (0xc2c0100b | (base << 5)) ||
                code[i - 4] != (0x5280000c | (off << 5)) ||
                code[i - 3] != 0x8b0c016b ||
                code[i - 2] != (0xc2cb400a | (base << 5)) ||
                code[i - 1] != (0xd280000c | ((1u << s) << 5)) ||
                code[i + 3] != (0xc2c0500b | (base << 5)) ||
                code[i + 4] != displacement || code[i + 5] != 0x8b0c016b ||
                code[i + 6] != 0xc2cb414a || code[i + 7] != memory)
                fail("FAIL incorrect access-contract machine code\n");
            windows++;
        }
    }
    if (frames > 1 || stack_windows != 2 * frames || windows != 4 ||
        loads != 3 + frames || stores != 1 + frames || gates != 1)
        fail("FAIL missing protected operation\n");
    return info.jited_prog_len;
}

static unsigned char expected[2][32];

static void reset_values(int fd)
{
    union bpf_attr update = {};
    __u32 key;

    update.map_fd = fd;
    update.key = (unsigned long)&key;
    for (key = 0; key < 2; key++) {
        for (unsigned int i = 0; i < 32; i++)
            expected[key][i] = 0x40 + 32 * key + i;
        expected[key][0] = key;
        update.value = (unsigned long)expected[key];
        if (bpf(BPF_MAP_UPDATE_ELEM, &update) < 0)
            fail("FAIL map initialization\n");
    }
}

static void readback(int fd, __u32 selected, unsigned int width)
{
    unsigned char actual[32];
    union bpf_attr attr = {};
    __u32 key;

    for (unsigned int i = 0; i < width; i++)
        expected[selected][16 + i] = expected[selected][8 + i];
    attr.map_fd = fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)actual;
    for (key = 0; key < 2; key++) {
        if (bpf(BPF_MAP_LOOKUP_ELEM, &attr) < 0)
            fail("FAIL map readback\n");
        for (unsigned int i = 0; i < 32; i++)
            if (actual[i] != expected[key][i])
                fail("FAIL value/adjacent-byte/neighbor-element mismatch\n");
    }
}

__attribute__((noreturn)) void _start(void)
{
    static const unsigned char sizes[] = { BPF_B, BPF_H, BPF_W, BPF_DW };
    static char log[16384];
    static unsigned char packet[64];
    union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .prog_flags = BPF_F_TEST_STATE_FREQ,
        .license = (unsigned long)"GPL",
        .prog_name = PROGRAM_NAME,
        .log_buf = (unsigned long)log,
        .log_size = sizeof(log),
        .log_level = 2, /* Retain the pruned-path trace, not just its summary. */
        .insns = (unsigned long)program,
        .insn_cnt = sizeof(program) / sizeof(program[0]),
    };
    union bpf_attr run = {
        .test = {
            .data_in = (unsigned long)packet,
            .data_size_in = sizeof(packet),
            .repeat = 1,
        },
    };
    int map_fd = create_array_map(BPF_F_MMAPABLE);

    program[0].imm = map_fd;
    for (unsigned int scale = 0; scale < 4; scale++) {
        program[16].code = BPF_LDX | BPF_MEM | sizes[scale];
        program[17].code = BPF_STX | BPF_MEM | sizes[scale];
        program[18].code = BPF_LDX | BPF_MEM | sizes[scale];
        for (__u32 key = 0; key < 2; key++) {
            int fd;
            unsigned int bytes;

            reset_values(map_fd);
            program[2].imm = key;
            fd = bpf(BPF_PROG_LOAD, &load);
            if (fd < 0) {
                say(log);
                fail("FAIL positive program load\n");
            }
            if (!scale && !key)
                check_pruned_join(log);
            bytes = inspect_jit(fd, scale);
            run.test.prog_fd = fd;
            if (bpf(BPF_PROG_TEST_RUN, &run) < 0 || run.test.retval != 42)
                fail("FAIL positive execution\n");
            readback(map_fd, key, 1u << scale);
            syscall3(__NR_close, fd, 0, 0);
            say("PASS width="); number(1u << scale);
            say(" key/branch="); number(key);
            say(" native_bytes="); number(bytes);
            say(" windows=4 join+SUB+negative-displacement+register-store+full-readback\n");
        }
    }
    syscall3(__NR_close, map_fd, 0, 0);
    say("PASS array access evaluation: 8/8 positive cases\n");
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}
