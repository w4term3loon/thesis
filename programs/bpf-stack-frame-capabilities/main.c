#ifndef PROGRAM_NAME
#define PROGRAM_NAME "stack_frame"
#endif
#include "../bpf-runtime.h"

/* A 64-byte frame. R6/R8 retain its first/last-byte pointers across lookup.
 * All bytecode accesses are valid, including in the expected-fault targets.
 */
static struct bpf_insn program[] = {
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_6, 0, 0, -64),
    INSN(BPF_ST | BPF_MEM | BPF_H, BPF_REG_6, 0, 0, 0x0b0a),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_6, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 64),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, -1),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_9, 0, 0, 20),
    INSN(BPF_STX | BPF_MEM | BPF_B, BPF_REG_8, BPF_REG_9, 0, 0),
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_10, 0, -8, 0),
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -8),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 7, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_W, BPF_REG_5, BPF_REG_0, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_7, BPF_REG_6, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_9, BPF_REG_8, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_5, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_7, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_9, 0, 0),
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

#ifndef EXPECTED_REJECTION
static void inspect_jit(int fd)
{
    static __u32 code[1024];
    struct bpf_prog_info info = {};
    union bpf_attr attr = {};
    unsigned int frames = 0, windows = 0, loads = 0, stores = 0, copies = 0;
    unsigned int integer_loads = 0;

    info.jited_prog_len = sizeof(code);
    info.jited_prog_insns = (unsigned long)code;
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0 || !info.jited_prog_len ||
        info.jited_prog_len > sizeof(code))
        fail("FAIL stack JIT inspection unavailable\n");
    for (unsigned int i = 0; i < info.jited_prog_len / 4; i++) {
        if (code[i] == 0xc2ca2339) { /* scbndse c25, c25, x10 */
            if (i < 3 || i + 4 >= info.jited_prog_len / 4 ||
                code[i - 3] != 0x028103ff || /* sub csp, csp, 64: retain its tag */
                code[i - 2] != 0xc2c1d3f9 || /* mov c25, csp */
                code[i - 1] != 0xd280080a || /* mov x10, 64 */
                code[i + 1] != 0xc2aa6339 || /* add c25, c25, x10 */
                code[i + 2] != 0x92a0006a || /* movn x10, 3, lsl 16 */
                code[i + 3] != 0xf29fffca || /* movk x10, 0xfffe */
                code[i + 4] != 0xc2caa339)   /* clrperm: global/load/store only */
                fail("FAIL stack root is not exact, frame-sized and permission-restricted\n");
            frames++;
        }
        copies += code[i] == 0xc2c1d333 || /* c19 = c25 (r6 = fp) */
                  code[i] == 0xc2c1d275 || /* c21 = c19 (r8 = r6) */
                  code[i] == 0xc2c1d321;   /* c1 = c25 (r2 = fp) */
        if (code[i] == 0xc2cc214a) {
            check_access_direction(code, info.jited_prog_len / 4, i);
            windows++;
        }
        loads += (code[i] & 0xff3ffc00) == 0xe2000400;
        stores += (code[i] & 0xff3ffc00) == 0xe2000000;
        integer_loads += code[i] == 0x39400154; /* ldrb w20, [x10] */
    }
#ifdef FRAME_ONLY_FAULT
    unsigned int expected_windows = 6; /* One load uses C_frame directly. */
#else
    unsigned int expected_windows = 7;
#endif
#ifdef AMBIENT_FAULT
    unsigned int expected_integer_loads = 1;
#else
    unsigned int expected_integer_loads = 0;
#endif
    if (frames != 1 || copies != 3 || windows != expected_windows ||
        loads != 4 - expected_integer_loads || stores != 3 ||
        integer_loads != expected_integer_loads)
        fail("FAIL missing stack capability operation or access window\n");
}
#endif

#ifdef CONCURRENT_INVOCATIONS
static long start_workers(void)
{
    /* clone(SIGCHLD, NULL): fork, retaining the same loaded program FD. */
    long child = syscall3(__NR_clone, 17, 0, 0);
    unsigned long mask = child ? 1 : 2;

    if (child < 0 || syscall3(__NR_sched_setaffinity, 0, sizeof(mask), (long)&mask) < 0)
        fail("FAIL two-CPU worker setup\n");
    return child;
}

static void wait_child(long child)
{
    int status;
    register long x0 __asm__("x0") = child;
    register long x1 __asm__("x1") = (long)&status;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x8 __asm__("x8") = __NR_wait4;

    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory", "cc");
    if (x0 != child || status)
        fail("FAIL concurrent child execution\n");
}
#endif

__attribute__((noreturn)) void _start(void)
{
    static char log[16384];
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
#ifndef EXPECTED_REJECTION
    static unsigned char packet[64];
    union bpf_attr run = {
        .test = {
            .data_in = (unsigned long)packet,
            .data_size_in = sizeof(packet),
            .repeat = 1,
        },
    };
#endif
    int map_fd = create_array_map(BPF_F_MMAPABLE), fd;

    set_array_value(map_fd, 0, 42);
    program[9].imm = map_fd;
    fd = bpf(BPF_PROG_LOAD, &load);
#ifdef EXPECTED_REJECTION
    if (fd != -524) { /* Kernel-internal ENOTSUPP: no JIT/interpreter fallback. */
        if (fd >= 0)
            syscall3(__NR_close, fd, 0, 0);
        say(log);
        fail("FAIL missing metadata was not rejected with ENOTSUPP\n");
    }
    say("PASS " EXPECTED_REJECTION "\n");
#else
    if (fd < 0) {
        say(log);
        fail("FAIL stack program load\n");
    }
    inspect_jit(fd);
#ifdef CONCURRENT_INVOCATIONS
    long child = start_workers();
#endif
#ifdef EXPECTED_FAULT
    say("EXPECT " PROGRAM_NAME ": " EXPECTED_FAULT "\n");
#endif
    run.test.prog_fd = fd;
    long result = bpf(BPF_PROG_TEST_RUN, &run);
#ifdef EXPECTED_FAULT
    (void)result;
    fail("FAIL expected capability fault; access returned\n");
#else
    if (result < 0 || run.test.retval != 72)
        fail("FAIL stack first/last byte or ARRAY lookup result\n");
#ifdef CONCURRENT_INVOCATIONS
    if (child) {
        wait_child(child);
        say("PASS same-program concurrent invocations: two pinned CPUs, both results=72\n");
    }
#else
    say("PASS stack frame: 64 bytes, first/last byte, copy+signed ADD, scalar store, lookup key, gateway preservation; result=72\n");
    say("PASS JIT: exact CSP-derived frame, data-only permissions, 7 object-base access windows\n");
#endif
    syscall3(__NR_close, fd, 0, 0);
#endif
#endif
    syscall3(__NR_close, map_fd, 0, 0);
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}
