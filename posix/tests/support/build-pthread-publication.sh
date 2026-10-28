#!/usr/bin/env bash
# Consume the existing SDK and standalone runtime; do not rebuild the SDK.
# Use the maintained runtime linker script so compiler TLS has a PT_TLS header.
set -eu
probe_output=${1:?usage: build-pthread-publication.sh output-elf [source.c]}
probe_source=${2:-services/posix/tests/native_pthread_publication.c}
x86_64-elf-gcc -O2 -Wall -Wextra -Werror -I user/libc-port/include \
  -isystem out/newlib-port/sdk/sysroot/include --sysroot=out/newlib-port/sdk/sysroot \
  -Lout/newlib-port/sdk/sysroot/lib -nostdlib -nostartfiles -static \
  -Wl,-T,user/runtime/linker.ld,-no-pie,-z,noexecstack \
  -o "$probe_output" "$probe_source" -Wl,--start-group \
  out/newlib-port/sdk/lib/crt0.o \
  out/continuous-native-check/x86_64-unknown-mochios/release/libmochi_user_newlib_runtime.a \
  out/continuous-native-check/native-probes/newlib_reent.o -lc -lm -lgcc -Wl,--end-group
x86_64-elf-readelf -lW "$probe_output" | rg -q '^  TLS '
