#!/usr/bin/env bash
# Host tests against the actual patched clangDriver/clangBasic libraries.
set -euo pipefail
if [[ $# -ne 6 ]]; then
    echo "usage: $0 LLVM_SOURCE LLVM_HOST_BUILD MOCHIOS_LD HOST_LD_LLD HOST_MSIGN SDK" >&2
    exit 2
fi
test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
llvm_source=$(realpath -- "$1")
llvm_build=$(realpath -- "$2")
compiler=${CXX:-c++}
test_tmp=$(mktemp -d "${TMPDIR:-/tmp}/clang-driver.XXXXXXXX")
trap 'rm -rf -- "$test_tmp"' EXIT

cmake --build "$llvm_build" --parallel 2 --target clangDriver
"$compiler" -std=c++17 -O0 -fno-rtti \
    -I"$llvm_source/clang/include" \
    -I"$llvm_build/tools/clang/include" \
    -I"$llvm_source/llvm/include" -I"$llvm_build/include" \
    -c "$test_dir/clang_driver.cpp" -o "$test_tmp/driver.o"
"$compiler" "$test_tmp/driver.o" -Wl,--start-group \
    "$llvm_build/lib/libclangDriver.a" "$llvm_build/lib/libclangBasic.a" \
    "$llvm_build"/lib/libLLVM*.a -Wl,--end-group \
    -lpthread -ldl -lrt -lm -o "$test_tmp/driver"
python3 "$test_dir/clang_driver.py" --driver "$test_tmp/driver" \
    --ld "$3" --lld "$4" --msign "$5" --sdk "$6" --cc "${CC:-clang}"
