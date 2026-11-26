#ifndef THESIS_BPF_RUNTIME_H
#define THESIS_BPF_RUNTIME_H

#include <asm/unistd.h>
#include <linux/bpf.h>

#define INSN(c, d, s, o, i) \
    { .code = (c), .dst_reg = (d), .src_reg = (s), .off = (o), .imm = (i) }

static inline long syscall3(long number, long a, long b, long c)
{
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x8 __asm__("x8") = number;

    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
    return x0;
}

static inline long bpf(enum bpf_cmd command, union bpf_attr *attr)
{
    return syscall3(__NR_bpf, command, (long)attr, sizeof(*attr));
}

static inline __attribute__((noreturn)) void fail(const char *message)
{
    unsigned long length = 0;

    while (message[length])
        length++;
    syscall3(__NR_write, 2, (long)message, length);
    syscall3(__NR_exit, 1, 0, 0);
    __builtin_unreachable();
}

/* Check the pinned JIT's temporary C10, not the unchanged object register.
 * 'i' identifies SCBNDSE; the effective-address sequence follows CLRPERM.
 */
static inline void check_access_direction(const __u32 *code, unsigned int count,
                                         unsigned int i)
{
    if (i + 7 >= count || code[i + 2] != 0xc2cca14a) /* clrperm c10,c10,x12 */
        fail("FAIL C_access permission attenuation missing\n");
    unsigned int m = i + 7;
    if ((code[m] & 0xff80001f) == 0xd280000b) /* immediate store value in x11 */
        m++;
    if (m >= count)
        fail("FAIL truncated C_access operation\n");
    __u32 op = code[m] & 0xff3fffe0;
#ifdef AMBIENT_FAULT
    if (code[m] == 0x39400154) /* Evaluation-only ordinary read through RDDC. */
        op = 0xe2000540;
#endif
    if ((op != 0xe2000540 && op != 0xe2000140) ||
        code[i + 1] != (op == 0xe2000540 ? 0x92a0004c : 0x92a0002c))
        fail("FAIL C_access does not retain only the access direction\n");
}

static inline int create_array_map(__u32 flags)
{
    static union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = 32,
        .max_entries = 2,
    };
    long fd;

    attr.map_flags = flags;
    fd = bpf(BPF_MAP_CREATE, &attr);
    if (fd < 0)
        fail("BPF_MAP_CREATE failed\n");
    return fd;
}

static inline void set_array_value(int fd, __u32 key, __u64 first_word)
{
    static __u64 value[4];
    static union bpf_attr attr;

    value[0] = first_word;
    attr.map_fd = fd;
    attr.key = (unsigned long)&key;
    attr.value = (unsigned long)value;
    if (bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0)
        fail("BPF_MAP_UPDATE_ELEM failed\n");
}

static inline __attribute__((noreturn)) void
run_bpf(struct bpf_insn *program, unsigned int count, unsigned int expected)
{
    static union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .license = (unsigned long)"GPL",
        .prog_name = PROGRAM_NAME,
    };
    static unsigned char packet[64];
    static union bpf_attr run = {
        .test = {
            .data_in = (unsigned long)packet,
            .data_size_in = sizeof(packet),
            .repeat = 1,
        },
    };
    long fd;

    load.insns = (unsigned long)program;
    load.insn_cnt = count;
    fd = bpf(BPF_PROG_LOAD, &load);
    if (fd < 0)
        fail("BPF_PROG_LOAD failed\n");
    run.test.prog_fd = fd;
    if (bpf(BPF_PROG_TEST_RUN, &run) < 0 || run.test.retval != expected)
        fail("BPF_PROG_TEST_RUN failed or returned an unexpected value\n");

    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}

#endif
