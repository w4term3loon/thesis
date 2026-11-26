# Sourced by build.sh and run.sh after setting root, build, and target.
if [[ ! "$target" =~ ^[a-z0-9][a-z0-9-]*$ || ! -f "$root/targets/$target.conf" ]]; then
    printf 'Unknown target: %s (see --help)\n' "$target" >&2
    exit 2
fi
program=
patches=()
config=
cpus=1
source "$root/targets/$target.conf"
if [[ ! "$program" =~ ^[a-z0-9][a-z0-9-]*$ || ! -f "$root/programs/$program/init" ||
      -z "$config" || ! -f "$root/$config" || ! "$cpus" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Invalid program or config in target: %s\n' "$target" >&2
    exit 2
fi

patch_files=()
shopt -s nullglob
for id in "${patches[@]}"; do
    [[ "$id" =~ ^[0-9]{4}$ ]] || { printf 'Invalid patch number: %s\n' "$id" >&2; exit 2; }
    matches=("$root/patches/$id-"*.patch)
    if [[ ${#matches[@]} != 1 ]]; then
        printf 'Expected exactly one patch numbered %s.\n' "$id" >&2
        exit 2
    fi
    patch_files+=("${matches[0]}")
done
if (( ${#patch_files[@]} )); then
    mapfile -t patch_files < <(printf '%s\n' "${patch_files[@]}" | LC_ALL=C sort -u)
fi

# Program choice is independent: targets may share the same kernel build.
kernel_key() {
    { git -C "$build/src/linux" rev-parse HEAD
      sha256sum "$build/src/linux/arch/arm64/configs/morello_pcuabi_defconfig" "$root/$config"
      if (( ${#patch_files[@]} )); then sha256sum -- "${patch_files[@]}"; fi
    } | sha256sum
}
