# CHERI-eBPF for Arm Morello

This prototype uses hardware-checked capabilities to confine supported eBPF
loads and stores to the stack frame, map value, or ring-buffer payload that
the kernel supplied. It extends Leaf's Morello Linux kernel. The examples
run as single-function socket filters in an emulated Morello guest.

## Run an example

Use an x86-64 Linux host. The build needs Bash, Git, Make, a C/C++ compiler,
Python 3, Ninja, pkg-config, flex, bison, bc, curl, dpkg-deb, gzip, and the
GLib, pixman, libfdt, OpenSSL, and ELF development headers. The first build
downloads the pinned QEMU, Linux, LLVM, and BusyBox inputs.

```sh
./scripts/run.sh --list
./scripts/run.sh --describe bpf-stack-only-capabilities
BUILD_JOBS=4 ./scripts/run.sh bpf-stack-only-capabilities
```

The guest prints the fixture's results and powers off. `BUILD_JOBS` defaults
to 4. Run one build or guest at a time because the scripts share `build/`.
`./scripts/build.sh TARGET` builds the kernel and guest image.
`./scripts/run.sh TARGET --no-build` reuses a build for the same target.

| Target | What it exercises |
| --- | --- |
| `bpf-stack-only-capabilities` | Invocation-local stack reads and writes |
| `bpf-integrated-array` | Reads, writes, and permissions on array values |
| `bpf-array-variable-access` | Access windows for variable offsets within a value |
| `bpf-ringbuf-hash-regression` | Hash lookups and value permissions |
| `bpf-ringbuf-payload-capabilities` | Reservation, payload access, and release |

## Read the implementation

- Start with the [implementation overview](docs/implementation.md).
- `targets/` selects an example, a kernel configuration, and an ordered
  patch series. `--describe TARGET` prints that selection.
- `patches/` contains the changes to the verifier, JIT, object providers,
  and gateways. A build applies them to `build/src/linux/`.
- `programs/` contains the examples and their result checks. `scripts/` and
  `initramfs/` build the kernel and launch the guest.
