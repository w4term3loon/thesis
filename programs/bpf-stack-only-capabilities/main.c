#define PROGRAM_NAME "stack_only"
#include "../bpf-runtime.h"

/* No map or helper: exercise the first and last bytes of a 64-byte frame. */
static struct bpf_insn program[] = {
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_10, 0, -64, 17),
    INSN(BPF_ST | BPF_MEM | BPF_B, BPF_REG_10, 0, -1, 25),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_0, BPF_REG_10, -64, 0),
    INSN(BPF_LDX | BPF_MEM | BPF_B, BPF_REG_1, BPF_REG_10, -1, 0),
    INSN(BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_0, BPF_REG_1, 0, 0),
    INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
};

static void say(const char *message)
{
    unsigned long length = 0;
    while (message[length])
        length++;
    syscall3(__NR_write, 1, (long)message, length);
}

static void inspect_jit(int fd)
{
    static __u32 code[512];
    struct bpf_prog_info info = {};
    union bpf_attr attr = {};
    unsigned int frames = 0, windows = 0, loads = 0, stores = 0, gates = 0;

    info.jited_prog_len = sizeof(code);
    info.jited_prog_insns = (unsigned long)code;
    attr.info.bpf_fd = fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (unsigned long)&info;
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0 || !info.jited_prog_len ||
        info.jited_prog_len > sizeof(code))
        fail("FAIL stack-only JIT inspection unavailable\n");

    for (unsigned int i = 0; i < info.jited_prog_len / 4; i++) {
        if (code[i] == 0xc2ca2339) { /* scbndse c25, c25, x10 */
            if (i < 3 || i + 4 >= info.jited_prog_len / 4 ||
                code[i - 3] != 0x028103ff || /* sub csp, csp, 64 */
                code[i - 2] != 0xc2c1d3f9 || /* mov c25, csp */
                code[i - 1] != 0xd280080a || /* mov x10, 64 */
                code[i + 1] != 0xc2aa6339 || /* add c25, c25, x10 */
                code[i + 2] != 0x92a0006a ||
                code[i + 3] != 0xf29fffca ||
                code[i + 4] != 0xc2caa339)   /* data-only clrperm */
                fail("FAIL stack-only frame is not exact and data-only\n");
            frames++;
        }
        if (code[i] == 0xc2cc214a) { /* scbndse c10, c10, x12 */
            check_access_direction(code, info.jited_prog_len / 4, i);
            windows++;
        }
        loads += (code[i] & 0xff3ffc00) == 0xe2000400;
        stores += (code[i] & 0xff3ffc00) == 0xe2000000;
        gates += code[i] == 0xc2c232e0; /* blr c23 */
    }
    if (frames != 1 || windows != 4 || loads != 2 || stores != 2 || gates)
        fail("FAIL stack-only capability operations or gateway count\n");
}

__attribute__((noreturn)) void _start(void)
{
    static char log[8192];
    static unsigned char packet[64];
    union bpf_attr load = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .license = (unsigned long)"GPL",
        .prog_name = PROGRAM_NAME,
        .insns = (unsigned long)program,
        .insn_cnt = sizeof(program) / sizeof(program[0]),
        .log_buf = (unsigned long)log,
        .log_size = sizeof(log),
        .log_level = 1,
    };
    union bpf_attr run = {
        .test = {
            .data_in = (unsigned long)packet,
            .data_size_in = sizeof(packet),
            .repeat = 1,
        },
    };
    long fd = bpf(BPF_PROG_LOAD, &load);

    if (fd < 0) {
        say(log);
        fail("FAIL stack-only program load\n");
    }
    inspect_jit(fd);
    run.test.prog_fd = fd;
    if (bpf(BPF_PROG_TEST_RUN, &run) < 0 || run.test.retval != 42)
        fail("FAIL stack-only program result\n");
    say("PASS mapless stack: frame=64 accesses=4 loads=2 stores=2 gateway=0 result=42\n");
    syscall3(__NR_close, fd, 0, 0);
    syscall3(__NR_exit, 0, 0, 0);
    __builtin_unreachable();
}
