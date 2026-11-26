#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build="$root/build"
jobs=${BUILD_JOBS:-4}

usage() {
    cat <<'USAGE'
Usage: ./scripts/build.sh TARGET
       ./scripts/run.sh TARGET [--no-build]
       ./scripts/run.sh --list
       ./scripts/run.sh --describe TARGET

Start with bpf-stack-only-capabilities or bpf-integrated-array.
--list shows the available examples.
--describe shows the example, configuration, and patches.
--no-build reuses a build, but does not check source freshness.
BUILD_JOBS sets build parallelism (default 4).

Targets explicitly select programs, ordered patches and kernel configuration.
USAGE
}

case ${1:-} in
    --help)
        [[ $# == 1 ]] || { usage >&2; exit 2; }
        usage
        exit 0
        ;;
    --list)
        [[ $# == 1 ]] || { usage >&2; exit 2; }
        exec "$root/scripts/targets.sh"
        ;;
    --describe)
        [[ $# == 2 ]] || { usage >&2; exit 2; }
        exec "$root/scripts/targets.sh" --describe "$2"
        ;;
esac
[[ $# == 1 ]] || { usage >&2; exit 2; }
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { printf 'BUILD_JOBS must be positive.\n' >&2; exit 2; }
target=$1
source "$root/scripts/target.sh"

mkdir -p "$build/src" "$build/qemu" "$build/kernel"

fetch() {
    local directory="$build/src/$1"
    local revision
    if [[ ! -d "$directory/.git" ]]; then
        git init "$directory"
        git -C "$directory" remote add origin "$2"
    fi
    if revision=$(git -C "$directory" rev-parse --verify HEAD 2>/dev/null); then
        if [[ "$revision" != "$3" ]]; then
            printf 'Unexpected %s revision: %s (expected %s). Checkout left untouched.\n' \
                "$1" "$revision" "$3" >&2
            exit 1
        fi
        return
    fi
    git -C "$directory" fetch --depth=1 origin "$3"
    git -C "$directory" checkout --detach "$3"
}

fetch qemu https://github.com/CTSRD-CHERI/qemu.git \
    d0bb921cd6d34d1f8f4b3dafd279aa571795c938
fetch llvm https://git.morello-project.org/morello/llvm-project-releases.git \
    1f0315052e50b295436df431575709ee30ce1968
fetch linux https://git.morello-project.org/morello/kernel/linux.git \
    dfcb2dc498ff214dc8b3d8117ef7e8c7e7901152

"$root/scripts/patches.sh" "${patch_files[@]}"

if [[ ! -f "$build/qemu/build.ninja" ]]; then
    (
        cd "$build/qemu"
        "$build/src/qemu/configure" \
            --target-list=morello-softmmu \
            --without-default-features \
            --enable-tcg --enable-fdt --meson=git \
            --disable-capstone --disable-slirp --disable-werror
    )
fi
ninja -C "$build/qemu" -j "$jobs" \
    qemu-system-morello pc-bios/edk2-aarch64-code.fd

kernel_args=(-C "$build/src/linux" O="$build/kernel" ARCH=arm64
             LLVM="$build/src/llvm/bin/" LLVM_IAS=1)
printf 'building\n' > "$build/kernel/selection.built"
# Start from the base every time so options cannot leak between stages.
(
    cd "$build/kernel"
    if [[ -f .config ]]; then cp .config .config.previous; fi
    "$build/src/linux/scripts/kconfig/merge_config.sh" -m -Q -O "$build/kernel" \
        "$build/src/linux/arch/arm64/configs/morello_pcuabi_defconfig" "$root/$config"
)
make "${kernel_args[@]}" olddefconfig
make "${kernel_args[@]}" -j "$jobs" Image headers
kernel_key > "$build/kernel/selection.built"

if [[ ! -x "$build/busybox/bin/busybox" ]]; then
    curl --fail --location \
        'https://deb.debian.org/debian/pool/main/b/busybox/busybox-static_1.35.0-4+deb12u1+b1_arm64.deb' \
        --output "$build/busybox.deb"
    printf '%s  %s\n' \
        732c9135564fc71337e0e05fb4da4d11e6c28c1834bce3e405e575afef2a52f5 \
        "$build/busybox.deb" | sha256sum --check --status
    dpkg-deb --extract "$build/busybox.deb" "$build/busybox"
fi

make -C "$root" -f scripts/guest.mk TARGET="$target" PROGRAM="$program"
cp "$root/targets/$target.conf" "$build/guests/$target/target.built"
