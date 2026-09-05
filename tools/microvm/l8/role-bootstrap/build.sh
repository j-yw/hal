#!/usr/bin/env bash
# Assemble and link freestanding static linux/amd64 hal-guest-role-bootstrap.
# Uses as/ld only. No gcc, libc, or Go toolchain.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build.sh <output-directory>" >&2
  exit 2
fi

out_dir="$1"
mkdir -p -- "$out_dir"
out_dir="$(cd -- "$out_dir" && pwd)"
src_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

(cd -- "$src_dir" && as --64 -I "$src_dir" -o "$out_dir/hal-guest-role-bootstrap.o" hal-guest-role-bootstrap.S)
ld -m elf_x86_64 -static -nostdlib --no-dynamic-linker -z noexecstack -e _start \
  -o "$out_dir/hal-guest-role-bootstrap" \
  "$out_dir/hal-guest-role-bootstrap.o"
