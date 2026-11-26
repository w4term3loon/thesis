#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ring_caps"
#endif
#include "../bpf-runtime.h"
#include <linux/mman.h>

#define RING_SIZE 4096
#define PAYLOAD_SIZE 31
#define RECORD_SIZE 40 /* Eight-byte header, payload, one byte of padding. */

/* Handwritten, verifier-valid BPF. One reservation and one release per run. */
static struct bpf_insn program[] = {
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_10, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_6, 0, 0, -16),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_6, 0, 0, 10),
    INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0, 0),
    { 0 },
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_2, 0, 0, PAYLOAD_SIZE),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, 0),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_reserve),
    INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 19, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_7, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_8, 0, 0, 30),
    INSN(BPF_ST | BPF_MEM | BPF_DW, BPF_REG_7, 0, 0, 0),
    INSN(BPF_ST | BPF_MEM | BPF_DW, BPF_REG_7, 0, 8, 0),
    INSN(BPF_ST | BPF_MEM | BPF_DW, BPF_REG_7, 0, 16, 0),
    INSN(BPF_ST | BPF_MEM | BPF_W, BPF_REG_7, 0, 24, 0),
    INSN(BPF_ST | BPF_MEM | BPF_H, BPF_REG_7, 0, 28, 0),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_7, 0, 0, 42),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_8, 0, 0, 99),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_9, BPF_REG_7, 0, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_5, BPF_REG_8, 0, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_9, BPF_REG_5, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_7, 0, 0),
    INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_2, 0, 0, 0),
    INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_ringbuf_submit),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_0, BPF_REG_6, 0, 0),
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

#ifndef EXPECTED_BOUNDS_FAULT
static void *map_region(int fd, unsigned long offset, unsigned long length, int prot)
{
    register long x0 __asm__("x0") = 0;
    register long x1 __asm__("x1") = length;
    register long x2 __asm__("x2") = prot;
    register long x3 __asm__("x3") = MAP_SHARED;
    register long x4 __asm__("x4") = fd;
    register long x5 __asm__("x5") = offset;
    register long x8 __asm__("x8") = __NR_mmap;

    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory", "cc");
    if (x0 < 0)
        fail("FAIL ring mmap\n");
    return (void *)x0;
}
#endif

static void inspect_jit(int fd, unsigned int release)
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
        fail("FAIL ring JIT inspection unavailable\n");
    for (unsigned int i = 0; i < info.jited_prog_len / 4; i++) {
        loads += (code[i] & 0xff3ffc00) == 0xe2000400;
        stores += (code[i] & 0xff3ffc00) == 0xe2000000;
        if (code[i] == 0xc2cc214a) {
            check_access_direction(code, info.jited_prog_len / 4, i);
            windows++;
        }
        frames += code[i] == 0xc2ca2339;
        if (code[i] == 0xc2c232e0) { /* blr c23 */
            unsigned int op = gates ? release : BPF_FUNC_ringbuf_reserve;

            if (i < 2 || i + 1 >= info.jited_prog_len / 4 ||
                code[i - 2] != 0x91000027 || /* scalar size/flags: x7 = x1 */
                code[i - 1] != (0xd280000c | (op << 5)) || /* trusted operation */
                code[i + 1] != 0xc2c1d31e) /* restore return sentry */
                fail("FAIL ring dedicated gateway sequence\n");
            gates++;
        }
    }
#ifdef EXPECTED_BOUNDS_FAULT
    unsigned int expected_windows = 10; /* One read uses C_payload directly. */
#else
    unsigned int expected_windows = 11;
#endif
    if (loads != 3 || stores != 8 || windows != expected_windows || gates != 2 || frames != 1)
        fail("FAIL ring capability operations or access windows missing\n");
}

static int load_program(int map_fd, unsigned int release)
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
    int fd;

    program[3].imm = map_fd;
    program[24].imm = release;
    fd = bpf(BPF_PROG_LOAD, &load);
    if (fd < 0) {
        say(log);
        fail("FAIL ring program load\n");
    }
    inspect_jit(fd, release);
    return fd;
}

static unsigned int run_program(int fd)
{
    static unsigned char packet[64];
    union bpf_attr run = {
        .test = {
            .prog_fd = fd,
            .data_in = (unsigned long)packet,
            .data_size_in = sizeof(packet),
            .repeat = 1,
        },
    };
    if (bpf(BPF_PROG_TEST_RUN, &run) < 0)
        fail("FAIL ring program execution\n");
    return run.test.retval;
}

#ifndef EXPECTED_BOUNDS_FAULT
static __u64 *consumer;
static const __u64 *producer;
static const unsigned char *data;

static void consume_one(int discard)
{
    __u64 pos = __atomic_load_n(consumer, __ATOMIC_ACQUIRE);
    const __u32 *header = (const __u32 *)(data + (pos & (RING_SIZE - 1)));
    __u32 expected = PAYLOAD_SIZE | (discard ? BPF_RINGBUF_DISCARD_BIT : 0);
    const unsigned char *payload = (const unsigned char *)header + BPF_RINGBUF_HDR_SZ;

    if (__atomic_load_n(producer, __ATOMIC_ACQUIRE) < pos + RECORD_SIZE ||
        __atomic_load_n(header, __ATOMIC_ACQUIRE) != expected)
        fail("FAIL ring header, publication or discard\n");
    if (!discard)
        for (unsigned int i = 0; i < PAYLOAD_SIZE; i++)
            if (payload[i] != (i == 0 ? 42 : i == 30 ? 99 : 0))
                fail("FAIL ring payload readback\n");
    __atomic_store_n(consumer, pos + RECORD_SIZE, __ATOMIC_RELEASE);
}
#endif

__attribute__((noreturn)) void _start(void)
{
    union bpf_attr create = { .map_type = BPF_MAP_TYPE_RINGBUF, .max_entries = RING_SIZE };
    int map_fd = bpf(BPF_MAP_CREATE, &create);
    int submit;

    if (map_fd < 0)
        fail("FAIL ring map creation\n");
    submit = load_program(map_fd, BPF_FUNC_ringbuf_submit);
#ifdef EXPECTED_BOUNDS_FAULT
    say("EXPECT " PROGRAM_NAME ": C_payload bounds fault, C_access bypassed for one read\n");
    run_program(submit);
    fail("FAIL expected ring bounds fault; access returned\n");
#else
    consumer = map_region(map_fd, 0, RING_SIZE, PROT_READ | PROT_WRITE);
    producer = map_region(map_fd, RING_SIZE, 3 * RING_SIZE, PROT_READ);
    data = (const unsigned char *)producer + RING_SIZE;
    if (run_program(submit) != 151)
        fail("FAIL ring first/last byte or gateway register preservation\n");
#ifdef EXPECTED_GATE_REJECTION
    consume_one(1);
    say("PASS shifted submit capability rejected; recorded reservation safely discarded\n");
#else
    consume_one(0);
    say("PASS ring submit: 31-byte payload, first/last byte, full readback; result=151\n");
    int discard = load_program(map_fd, BPF_FUNC_ringbuf_discard);
    if (run_program(discard) != 151)
        fail("FAIL ring discard execution\n");
    consume_one(1);
    syscall3(__NR_close, discard, 0, 0);
    say("PASS ring discard: reservation released, no published payload\n");

    /* Advance by real reserve/consume operations, without changing metadata. */
    while (__atomic_load_n(producer, __ATOMIC_ACQUIRE) < RING_SIZE) {
        if (run_program(submit) != 151)
            fail("FAIL ring wraparound execution\n");
        consume_one(0);
    }
    say("PASS ring wraparound: payload spans both virtual aliases, full readback\n");

    for (unsigned int i = 0; i < (RING_SIZE - 1) / RECORD_SIZE; i++)
        if (run_program(submit) != 151)
            fail("FAIL ring fill\n");
    __u64 before = __atomic_load_n(producer, __ATOMIC_ACQUIRE);
    if (run_program(submit) != 0 || __atomic_load_n(producer, __ATOMIC_ACQUIRE) != before)
        fail("FAIL ring full/NULL path changed producer state\n");
    while (__atomic_load_n(consumer, __ATOMIC_ACQUIRE) < before)
        consume_one(0);
    if (run_program(submit) != 151)
        fail("FAIL ring recovery after NULL reservation\n");
    consume_one(0);
    say("PASS ring full: NULL, unchanged producer, successful reserve after consumption\n");
    say("PASS ring JIT: 11 access windows, exact frame, two dedicated gateways\n");
#endif
    syscall3(__NR_munmap, (long)consumer, RING_SIZE, 0);
    syscall3(__NR_munmap, (long)producer, 3 * RING_SIZE, 0);
    syscall3(__NR_close, submit, 0, 0);
    syscall3(__NR_close, map_fd, 0, 0);
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
#endif
}
