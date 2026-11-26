#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build="$root/build"
case ${1:-} in
    --help|--list|--describe) exec "$root/scripts/build.sh" "$@" ;;
esac
if [[ $# -lt 1 || $# -gt 2 || ( $# == 2 && $2 != --no-build ) ]]; then
    "$root/scripts/build.sh" --help >&2
    exit 2
fi
target=$1
source "$root/scripts/target.sh"
if [[ ${2:-} == --no-build ]]; then
    if [[ ! -f "$build/kernel/selection.built" ||
          $(< "$build/kernel/selection.built") != "$(kernel_key)" ]]; then
        printf 'The selected patches/config have not been built. Omit --no-build.\n' >&2
        exit 1
    fi
    if [[ ! -f "$build/guests/$target/initramfs.cpio.gz" ]] ||
       ! cmp -s "$root/targets/$target.conf" "$build/guests/$target/target.built"; then
        printf 'Build target %s first (omit --no-build).\n' "$target" >&2
        exit 1
    fi
else
    "$root/scripts/build.sh" "$target"
fi

exec "$build/qemu/qemu-system-morello" \
    -M virt,gic-version=3 -cpu morello -accel tcg \
    -m 2G -smp "$cpus" \
    -bios "$build/qemu/pc-bios/edk2-aarch64-code.fd" \
    -kernel "$build/kernel/arch/arm64/boot/Image" \
    -initrd "$build/guests/$target/initramfs.cpio.gz" \
    -append 'console=ttyAMA0 loglevel=7 rdinit=/init panic=-1' \
    -nic none -display none -monitor none -serial stdio -no-reboot
