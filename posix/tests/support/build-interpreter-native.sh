#!/usr/bin/env bash
# Consume the existing SDK, never build or publish it.
set -eu
fixture_out=${1:?usage: build-interpreter-native.sh output-directory}
fixture_support=services/posix/tests/support
mkdir -p "$fixture_out"
x86_64-elf-gcc -nostdlib -Wl,-shared,-z,noexecstack,-e,_start,--no-dynamic-linker \
  "$fixture_support/native_interpreter.S" -o "$fixture_out/ld.native.so"
x86_64-elf-gcc -O2 -fno-pie -Wall -Wextra -Werror -I user/libc-port/include \
  -isystem out/newlib-port/sdk/sysroot/include --sysroot=out/newlib-port/sdk/sysroot \
  -Lout/newlib-port/sdk/sysroot/lib -nostdlib -nostartfiles -static \
  -Wl,-T,"$fixture_support/native_interpreter.ld",-no-pie,-z,noexecstack \
  -o "$fixture_out/native_interpreter_app.elf" services/posix/tests/native_interpreter_app.c \
  "$fixture_support/native_interpreter_root.S" -Wl,--start-group \
  out/newlib-port/sdk/lib/crt0.o \
  out/continuous-native-check/x86_64-unknown-mochios/release/libmochi_user_newlib_runtime.a \
  out/continuous-native-check/native-probes/newlib_reent.o -lc -lm -lgcc -Wl,--end-group
x86_64-elf-readelf -lW "$fixture_out/native_interpreter_app.elf" > "$fixture_out/root.headers"
x86_64-elf-readelf -lWr "$fixture_out/ld.native.so" > "$fixture_out/interpreter.headers"
rg 'INTERP' "$fixture_out/root.headers"
rg 'There are no relocations' "$fixture_out/interpreter.headers"
