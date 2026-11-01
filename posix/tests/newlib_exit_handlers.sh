#!/usr/bin/env bash
# Compile the real newlib registry with target headers and a host allocator.
set -euo pipefail
if [[ $# -ne 2 ]]; then
    echo "usage: $0 NEWLIB_SOURCE SDK" >&2
    exit 2
fi
test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
newlib_source=$(realpath -- "$1")
sdk=$(realpath -- "$2")
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/newlib-exit.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT
compiler=${CC:-cc}
for source in __atexit __call_atexit; do
    "$compiler" -std=c11 -O1 -g -fsanitize=address,undefined \
        -isystem "$sdk/sysroot/include" -D__mochios__ -D__SINGLE_THREAD__ \
        -D__register_exitproc=newlib_register_exitproc \
        -D__call_exitprocs=newlib_call_exitprocs \
        -D__atexit=newlib_exit_head -D__atexit0=newlib_exit_first \
        -Dmalloc=registry_malloc -Dfree=registry_free \
        -c "$newlib_source/newlib/libc/stdlib/$source.c" \
        -o "$test_tmp/$source.o"
done
"$compiler" -std=c11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=address,undefined "$test_dir/newlib_exit_handlers.c" \
    "$test_tmp/__atexit.o" "$test_tmp/__call_atexit.o" \
    -o "$test_tmp/test"
for case_name in many dso allocation registration; do
    UBSAN_OPTIONS=halt_on_error=1 "$test_tmp/test" "$case_name"
done
