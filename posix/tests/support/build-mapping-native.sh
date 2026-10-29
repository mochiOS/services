#!/usr/bin/env bash
# Syscall-free DSO fixtures; no SDK or runtime generation.
set -eu
fixture_out=${1:?usage: build-mapping-native.sh output-directory}
mkdir -p "$fixture_out"
fixture_source=services/posix/tests/support/native_mapping_library.c
x86_64-elf-gcc -O2 -fPIC -ffreestanding -fno-stack-protector -nostdlib \
  -Wl,-shared,-z,noexecstack,-soname,libmapping.so \
  "$fixture_source" -o "$fixture_out/libmapping.so"
x86_64-elf-gcc -O2 -fPIC -ffreestanding -fno-stack-protector -nostdlib -DROOT \
  -Wl,-shared,-z,noexecstack,-e,_start -L"$fixture_out" \
  "$fixture_source" -l:libmapping.so -o "$fixture_out/root.so"
x86_64-elf-readelf -lWr "$fixture_out/root.so" > "$fixture_out/root.layout"
x86_64-elf-readelf -lWr "$fixture_out/libmapping.so" > "$fixture_out/library.layout"
