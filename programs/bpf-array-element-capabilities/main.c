#define PROGRAM_NAME "array_caps"
#include "../bpf-runtime.h"

/* Handwritten BPF. The final byte is 30: byte 31 is storage padding. */
static struct bpf_insn program[] = {
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -4, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 11, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_0, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_7, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 30),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_9, BPF_REG_8, 0, 0),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_8, 0, 0, 99),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_5, BPF_REG_8, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_9, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_5, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 7),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
};

static void say(const char *message)
{
    unsigned long length = 0;

    while (message[length])
        length++;
    syscall3(__NR_write, 1, (long)message, length);
}

static int create_map(__u32 flags)
{
    static union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = 31,
        .max_entries = 2,
    };
    static unsigned char value[31];
    static union bpf_attr update;
    __u32 key;
    int fd;

    attr.map_flags = BPF_F_MMAPABLE | flags;
    fd = bpf(BPF_MAP_CREATE, &attr);
    if (fd < 0)
        fail("BPF_MAP_CREATE failed\n");
    update.map_fd = fd;
    update.key = (unsigned long)&key;
    update.value = (unsigned long)value;
    for (key = 0; key < 2; key++) {
        value[0] = 10 + key;
        value[30] = 20 + key;
        if (bpf(BPF_MAP_UPDATE_ELEM, &update) < 0)
            fail("BPF_MAP_UPDATE_ELEM failed\n");
    }
    return fd;
}

/* Inspect the emitted A64 capability-base memory instructions, not just logs. */
static void check_native_code(int fd, unsigned int expected_stores,
                              unsigned int displacement)
{
    static __u32 code[512];
    static struct bpf_prog_info info;
    static union bpf_attr attr;
    unsigned int loads = 0, stores = 0, gates = 0, windows = 0;
    unsigned int frames = 0, stack_windows = 0;

    /* GET_INFO returns counts that must not become inputs to the next call. */
    for (unsigned int i = 0; i < sizeof(info); i++)
        ((volatile unsigned char *)&info)[i] = 0;
    info.jited_prog_len = sizeof(code);
    info.jited_prog_insns = (unsigned long)code;
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0 || !info.jited_prog_len ||
        info.jited_prog_len > sizeof(code))
        fail("JIT code inspection failed\n");
    for (unsigned int i = 0; i < info.jited_prog_len / sizeof(code[0]); i++) {
        loads += (code[i] & 0xff3ffc00) == 0xe2000400;
        stores += (code[i] & 0xff3ffc00) == 0xe2000000;
        gates += code[i] == 0xc2c232e0; /* blr c23 */
        frames += code[i] == 0xc2ca2339; /* patch 6: bound C25 to the frame */
        if (code[i] == 0xc2cc214a) { /* scbndse c10, c10, x12 (patch 4) */
            unsigned int base, offset, actual_off;

            check_access_direction(code, info.jited_prog_len / 4, i);
            if (i < 5 || i + 7 >= info.jited_prog_len / sizeof(code[0]))
                fail("Truncated access window sequence\n");
            base = (code[i - 5] >> 5) & 31;
            if (base == 25 || base == 1) { /* key store and inlined key read */
                stack_windows++;
                continue;
            }
            offset = base == 19 ? 0 : 30;
            actual_off = base == 19 ? 0 : displacement;
            /* Bounds use GCBASE + verifier offset, then GCVALUE + insn offset
             * installs the actual cursor without changing those bounds.
             */
            if ((base != 19 && base != 21) ||
                code[i - 5] != (0xc2c0100b | (base << 5)) || /* gcbase */
                code[i - 4] != (0x5280000c | (offset << 5)) || /* mov w12 */
                code[i - 3] != 0x8b0c016b ||                 /* add x11 */
                code[i - 2] != (0xc2cb400a | (base << 5)) || /* scvalue */
                code[i - 1] != 0xd280002c ||                 /* size = 1 */
                code[i + 3] != (0xc2c0500b | (base << 5)) || /* gcvalue */
                code[i + 4] != (0xd280000c | (actual_off << 5)) ||
                code[i + 5] != 0x8b0c016b ||
                code[i + 6] != 0xc2cb414a)                  /* scvalue */
                fail("Access window is not independent of the runtime cursor\n");
            if ((code[i + 7] & 0xffffffe0) != 0xe2000540 && /* ldrb [c10] */
                (i + 8 >= info.jited_prog_len / sizeof(code[0]) ||
                 code[i + 7] != 0xd2800c6b ||               /* mov x11, 99 */
                 code[i + 8] != 0xe200014b))                /* strb w11, [c10] */
                fail("Memory access does not use the narrowed capability\n");
            windows++;
        }
    }
    if (frames > 1 || stack_windows != 2 * frames ||
        loads != 3 + frames || stores != expected_stores + frames || gates != 1)
        fail("Expected capability loads/stores and derivation gate not emitted\n");
    if (windows && windows + stack_windows != loads + stores)
        fail("Missing per-access capability window\n");
    if (windows)
        say("PASS JIT access windows: element-base bounds, separate runtime cursor, read/write-only permissions\n");
}

static void run_case(int map_fd, __u32 key, unsigned int expected,
                     int readonly, const char *message)
{
    static char log[8192];
    static unsigned char packet[64], value[31];
    static union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .license = (unsigned long)"GPL",
        .prog_name = PROGRAM_NAME,
        .log_buf = (unsigned long)log,
        .log_size = sizeof(log),
        .log_level = 1,
    };
    static union bpf_attr run = {
        .test = {
            .data_in = (unsigned long)packet,
            .data_size_in = sizeof(packet),
            .repeat = 1,
        },
    };
    static union bpf_attr lookup;
    unsigned int displacement = key == 1 ? 14 : 0;
    int fd;

    program[0].imm = map_fd;
    program[2].imm = key;
    /* Both spellings access byte 30: p + 30, or (p + 16) + 14. */
    program[10].imm = 30 - displacement;
    program[11].off = displacement;
    program[12] = readonly ? (struct bpf_insn)
        INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 0) :
        (struct bpf_insn)INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_8, 0, displacement, 99);
    program[13].off = displacement;
    load.insns = (unsigned long)program;
    load.insn_cnt = sizeof(program) / sizeof(program[0]);
    fd = bpf(BPF_PROG_LOAD, &load);
    if (fd < 0) {
        say(log);
        fail("BPF_PROG_LOAD failed\n");
    }
    check_native_code(fd, !readonly, displacement);
    run.test.prog_fd = fd;
    if (bpf(BPF_PROG_TEST_RUN, &run) < 0 || run.test.retval != expected)
        fail("BPF_PROG_TEST_RUN failed or returned an unexpected value\n");
    syscall3(__NR_close, fd, 0, 0);

    if (key < 2) {
        lookup.map_fd = map_fd;
        lookup.key = (unsigned long)&key;
        lookup.value = (unsigned long)value;
        if (bpf(BPF_MAP_LOOKUP_ELEM, &lookup) < 0 || value[0] != 10 + key ||
            value[30] != (readonly ? 20 + key : 99))
            fail("Array value readback mismatch\n");
    }
    say(message);
}

__attribute__((noreturn)) void _start(void)
{
    int fd = create_map(0);

    run_case(fd, 0, 129, 0, "PASS rw element 0: first/last byte, copy, offset, write\n");
    run_case(fd, 1, 131, 0, "PASS rw element 1: first/last byte, copy, offset, write\n");
    run_case(fd, 2, 7, 0, "PASS missing key: NULL branch, no value access\n");
    syscall3(__NR_close, fd, 0, 0);
    fd = create_map(BPF_F_RDONLY_PROG);
    run_case(fd, 0, 50, 1, "PASS readonly element 0: first/last byte, copy, offset\n");
    run_case(fd, 1, 53, 1, "PASS readonly element 1: first/last byte, copy, offset\n");
    syscall3(__NR_close, fd, 0, 0);
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}
