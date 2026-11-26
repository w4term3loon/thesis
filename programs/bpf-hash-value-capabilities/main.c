#ifndef PROGRAM_NAME
#define PROGRAM_NAME "hash_caps"
#endif
#include "../bpf-runtime.h"

/* Valid handwritten BPF: keep a frame pointer across the trusted lookup,
 * then read the first/last value bytes and optionally write the last byte.
 */
static struct bpf_insn program[] = {
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_6, 0, 0, -32),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_6, 0, 0, 10),
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -8, 0),
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -8),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 10, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_7, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 31),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_9, BPF_REG_7, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_0, BPF_REG_8, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_9, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_5, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_5, 0, 0),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_8, 0, 0, 99),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
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
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = 32,
        .max_entries = 2,
        .map_flags = BPF_F_NO_PREALLOC | flags,
    };
    unsigned char value[32] = {};
    union bpf_attr update = {};
    __u32 key;
    int fd = bpf(BPF_MAP_CREATE, &attr);

    if (fd < 0)
        fail("FAIL HASH map creation\n");
    update.map_fd = fd;
    update.key = (unsigned long)&key;
    update.value = (unsigned long)value;
    for (unsigned int i = 0; i < 2; i++) {
        key = i ? 19 : 7; /* Non-contiguous keys; never array indices. */
        value[0] = 42 + i;
        value[31] = 20 + i;
        if (bpf(BPF_MAP_UPDATE_ELEM, &update) < 0)
            fail("FAIL HASH entry creation\n");
    }
    return fd;
}

static void inspect_jit(int fd, int readonly)
{
    static __u32 code[1024];
    struct bpf_prog_info info = {};
    union bpf_attr attr = {};
    unsigned int loads = 0, stores = 0, windows = 0, gates = 0, frames = 0;

    info.jited_prog_len = sizeof(code);
    info.jited_prog_insns = (unsigned long)code;
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0 || !info.jited_prog_len ||
        info.jited_prog_len > sizeof(code))
        fail("FAIL HASH JIT inspection unavailable\n");
    for (unsigned int i = 0; i < info.jited_prog_len / 4; i++) {
        loads += (code[i] & 0xff3ffc00) == 0xe2000400;
        stores += (code[i] & 0xff3ffc00) == 0xe2000000;
        if (code[i] == 0xc2cc214a) {
            check_access_direction(code, info.jited_prog_len / 4, i);
            windows++;
        }
        frames += code[i] == 0xc2ca2339; /* scbndse c25, c25, x10 */
        if (code[i] == 0xc2c232e0) { /* blr c23 */
            /* The gateway takes a scalar key, read through C_access.
             * Check its four-byte bounds and capability-base load.
             */
            if (i < 13 || i + 1 >= info.jited_prog_len / 4 ||
                code[i - 13] != 0xc2c0102b || /* gcbase x11, c1 */
                code[i - 12] != 0x5280030c || /* window offset = 32 - 8 */
                code[i - 9] != 0xd280008c ||  /* size = 4 */
                code[i - 8] != 0xc2cc214a ||  /* exact bounds */
                code[i - 5] != 0xc2c0502b ||  /* gcvalue x11, c1 */
                code[i - 2] != 0xc2cb414a ||  /* separate runtime cursor */
                code[i - 1] != 0xe2800547 ||  /* ldr w7, [c10] */
                code[i + 1] != 0xc2c1d31e)   /* restore return sentry */
                fail("FAIL HASH gateway key is not a bounded scalar read\n");
            gates++;
        }
    }
#ifdef EXPECTED_METADATA_FAULT
    unsigned int expected_windows = 6; /* One access uses C_value directly. */
#else
    unsigned int expected_windows = 7 - readonly;
#endif
    if (loads != 4 || stores != 3U - readonly || windows != expected_windows ||
        gates != 1 || frames != 1)
        fail("FAIL HASH capability operations or access windows missing\n");
}

#ifndef EXPECTED_METADATA_FAULT
static void check_values(int fd, unsigned int written)
{
    unsigned char value[32];
    __u32 key;
    union bpf_attr lookup = {
        .map_fd = fd,
        .key = (unsigned long)&key,
        .value = (unsigned long)value,
    };

    for (unsigned int i = 0; i < 2; i++) {
        key = i ? 19 : 7;
        if (bpf(BPF_MAP_LOOKUP_ELEM, &lookup) < 0)
            fail("FAIL HASH readback lookup\n");
        for (unsigned int j = 0; j < sizeof(value); j++) {
            unsigned int expected = j == 0 ? 42 + i : j == 31 ?
                (written & (1U << i) ? 99 : 20 + i) : 0;
            if (value[j] != expected)
                fail("FAIL HASH full-value readback\n");
        }
    }
}
#endif

static void run_case(int map_fd, __u32 key, int readonly, unsigned int expected,
                     unsigned int written, const char *message)
{
    static char log[8192];
    static unsigned char packet[64];
    union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .license = (unsigned long)"GPL",
        .prog_name = PROGRAM_NAME,
        .log_buf = (unsigned long)log,
        .log_size = sizeof(log),
        .log_level = 1,
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
    int fd;

    program[3].imm = key;
    program[4].imm = map_fd;
    program[18] = readonly ? (struct bpf_insn)
        INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_5, 0, 0, 0) :
        (struct bpf_insn)INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_8, 0, 0, 99);
    fd = bpf(BPF_PROG_LOAD, &load);
    if (fd < 0) {
        say(log);
        fail("FAIL HASH program load\n");
    }
    inspect_jit(fd, readonly);
    run.test.prog_fd = fd;
#ifdef EXPECTED_METADATA_FAULT
    (void)expected;
    (void)written;
    (void)message;
    say("EXPECT HASH value-base minus 16: entry hash field; C_value bounds fault\n");
    bpf(BPF_PROG_TEST_RUN, &run);
    fail("FAIL expected HASH metadata bounds fault; access returned\n");
#else
    if (bpf(BPF_PROG_TEST_RUN, &run) < 0 || run.test.retval != expected)
        fail("FAIL HASH return value or preserved frame pointer\n");
    check_values(map_fd, written);
    say(message);
    syscall3(__NR_close, fd, 0, 0);
#endif
}

__attribute__((noreturn)) void _start(void)
{
    int fd = create_map(0);

    run_case(fd, 7, 0, 72, 1, "PASS HASH RW key 7: first/last byte, write, preserved stack; result=72\n");
    run_case(fd, 19, 0, 74, 3, "PASS HASH RW key 19: independent entry, full readback; result=74\n");
    run_case(fd, 99, 0, 0, 3, "PASS HASH missing key: NULL, entries unchanged\n");
    syscall3(__NR_close, fd, 0, 0);
    fd = create_map(BPF_F_RDONLY_PROG);
    run_case(fd, 7, 1, 72, 0, "PASS HASH readonly key 7: first/last byte, entries unchanged\n");
    run_case(fd, 19, 1, 74, 0, "PASS HASH readonly key 19: first/last byte, entries unchanged\n");
    say("PASS HASH JIT: exact frame/access bounds, bounded scalar key, capability gateway\n");
    syscall3(__NR_close, fd, 0, 0);
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}
