#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build="$root/build"
source_dir="$build/src/linux"
state="$build/patches"

die() { printf '%s\n' "$*" >&2; exit 1; }
[[ -d "$source_dir/.git" ]] || die 'Build the kernel first with scripts/build.sh TARGET.'

# The target loader supplies resolved patch files in application order.
patches=("$@")
for patch in "${patches[@]}"; do
    [[ -f "$patch" ]] || die "Patch file not found: $patch"
done
key=$(
    { git -C "$source_dir" rev-parse HEAD
      if (( ${#patches[@]} )); then sha256sum -- "${patches[@]}"; fi
    } | sha256sum
)
key=${key%% *}

# The index holds only our managed changes; unstaged edits belong to the user.
if [[ -f "$state/applied.patch" ]]; then
    git -C "$source_dir" diff --cached --binary --no-color | cmp -s "$state/applied.patch" - ||
        die 'Kernel index differs from the managed patches; leaving it untouched.'
else
    git -C "$source_dir" diff --cached --quiet || die 'Kernel has staged edits; leaving them untouched.'
fi
if [[ -f "$state/key" && $(< "$state/key") == "$key" ]]; then
    exit 0
fi
git -C "$source_dir" diff --quiet ||
    die 'Cannot switch patches with local kernel edits. Save them first; nothing was changed.'

# Resolve the entire new selection against HEAD without changing the checkout.
patch_tmp=$(mktemp -d "$build/patch-switch.XXXXXX")
cleanup() {
    rm -f -- "$patch_tmp/index" "$patch_tmp/index.lock" "$patch_tmp/patch" "$patch_tmp/delta"
    rmdir -- "$patch_tmp"
}
trap cleanup EXIT
GIT_INDEX_FILE="$patch_tmp/index" git -C "$source_dir" read-tree HEAD
for patch in "${patches[@]}"; do
    GIT_INDEX_FILE="$patch_tmp/index" git -C "$source_dir" apply --cached "$patch"
done
GIT_INDEX_FILE="$patch_tmp/index" git -C "$source_dir" diff --cached --binary --no-color > "$patch_tmp/patch"

# Apply only the difference, preserving unchanged headers and incremental builds.
old_tree=$(git -C "$source_dir" write-tree)
GIT_INDEX_FILE="$patch_tmp/index" git -C "$source_dir" diff --cached --binary --no-color "$old_tree" > "$patch_tmp/delta"
if [[ -s "$patch_tmp/delta" ]]; then
    git -C "$source_dir" apply --index "$patch_tmp/delta" ||
        die 'Could not apply the selection; the previous selection was left untouched.'
fi
mkdir -p "$state"
cp "$patch_tmp/patch" "$state/applied.patch"
printf '%s\n' "$key" > "$state/key"
