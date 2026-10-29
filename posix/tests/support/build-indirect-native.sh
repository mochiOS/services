#!/usr/bin/env bash
# Consume the existing SDK and standalone runtime; never build/publish an SDK.
set -eu
fixture_out=${1:?usage: build-indirect-native.sh output-directory}
fixture_support=services/posix/tests/support
mkdir -p "$fixture_out"
x86_64-elf-gcc -O2 -fPIC -ffreestanding -fno-stack-protector -nostdlib \
  -isystem out/newlib-port/sdk/sysroot/include -ftls-model=initial-exec \
  -Wl,-shared,-z,noexecstack,-soname,libnative_ifunc.so,--hash-style=both \
  "$fixture_support/native_ifunc_library.c" -o "$fixture_out/libnative_ifunc.so"
x86_64-elf-gcc -O2 -fPIC -Wall -Wextra -Werror -I user/libc-port/include \
  -isystem out/newlib-port/sdk/sysroot/include --sysroot=out/newlib-port/sdk/sysroot \
  -Lout/newlib-port/sdk/sysroot/lib -nostdlib -nostartfiles \
  -Wl,-T,"$fixture_support/native_dynamic.ld",-no-pie,-z,noexecstack,--export-dynamic,--no-dynamic-linker \
  -Wl,-rpath,/system/libraries/ifunc-startup-290,--enable-new-dtags \
  -o "$fixture_out/native_indirect_app.elf" services/posix/tests/native_indirect_app.c \
  "$fixture_support/native_ifunc_copy.S" \
  -L"$fixture_out" -Wl,--no-as-needed -lnative_ifunc -Wl,--start-group \
  out/newlib-port/sdk/lib/crt0.o \
  out/continuous-native-check/x86_64-unknown-mochios/release/libmochi_user_newlib_runtime.a \
  out/continuous-native-check/native-probes/newlib_reent.o -lc -lm -lgcc -Wl,--end-group
x86_64-elf-readelf -rW "$fixture_out/native_indirect_app.elf" > "$fixture_out/root.relocations"
x86_64-elf-readelf -rW "$fixture_out/libnative_ifunc.so" > "$fixture_out/library.relocations"
rg 'native_pick' "$fixture_out/root.relocations" "$fixture_out/library.relocations"
rg 'R_X86_64_IRELATIVE' "$fixture_out/library.relocations"
rg 'R_X86_64_COPY' "$fixture_out/root.relocations"
rg 'R_X86_64_IRELATIVE' "$fixture_out/root.relocations"
