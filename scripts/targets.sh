#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

if [[ $# == 0 ]]; then
    for definition in "$root"/targets/*.conf; do
        name=${definition##*/}
        printf '%s\n' "${name%.conf}"
    done
    exit 0
fi

if [[ $# != 2 || $1 != --describe ]]; then
    printf 'Usage: ./scripts/targets.sh [--describe TARGET]\n' >&2
    exit 2
fi

target=$2
source "$root/scripts/target.sh"
printf 'Target: %s\nProgram: programs/%s/\nConfig: %s\nGuest CPUs: %s\n' \
    "$target" "$program" "$config" "$cpus"
printf '\nKernel patches, in application order:\n'
printf '  %s\n' "${patch_files[@]#"$root/"}"
