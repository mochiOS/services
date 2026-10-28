#!/usr/bin/env bash
# Consume the existing SDK and standalone runtime without rebuilding the SDK.
set -eu
fixture_out=${1:?usage: build-copy-native.sh output-directory}
fixture_support=services/posix/tests/support
mkdir -p "$fixture_out/good" "$fixture_out/bad"
for name in copy_library.c copy_fixture.h copy_library.map; do
  sed 's/API_2/API_3/g' "$fixture_support/$name" > "$fixture_out/bad/$name"
done
for kind in good bad; do
  if test "$kind" = good; then
    fixture_source="$fixture_support/copy_library.c"
    fixture_map="$fixture_support/copy_library.map"
  else
    fixture_source="$fixture_out/bad/copy_library.c"
    fixture_map="$fixture_out/bad/copy_library.map"
  fi
  x86_64-elf-gcc -O2 -fPIC -ffreestanding -fno-stack-protector -nostdlib \
    -Wl,-shared,-z,noexecstack,-soname,libcopy.so,--hash-style=both \
    -Wl,--version-script,"$fixture_map" "$fixture_source" -o "$fixture_out/$kind/libcopy.so"
done
for kind in good bad; do
  x86_64-elf-gcc -O2 -fno-pic -Wall -Wextra -Werror -I user/libc-port/include \
    -isystem out/newlib-port/sdk/sysroot/include --sysroot=out/newlib-port/sdk/sysroot \
    -Lout/newlib-port/sdk/sysroot/lib -nostdlib -nostartfiles \
    -Wl,-T,"$fixture_support/native_dynamic.ld",-no-pie,-z,noexecstack,--export-dynamic,--no-dynamic-linker \
    -Wl,-rpath,/tmp/copy-relocations-266/"$kind",--enable-new-dtags \
    -o "$fixture_out/$kind.elf" services/posix/tests/native_copy_app.c \
    -L"$fixture_out/good" -Wl,--no-as-needed -lcopy -Wl,--start-group \
    out/newlib-port/sdk/lib/crt0.o \
    out/continuous-native-check/x86_64-unknown-mochios/release/libmochi_user_newlib_runtime.a \
    out/continuous-native-check/native-probes/newlib_reent.o -lc -lm -lgcc -Wl,--end-group
  x86_64-elf-readelf -rW "$fixture_out/$kind.elf" > "$fixture_out/$kind.relocations"
  test "$(rg -c 'R_X86_64_COPY' "$fixture_out/$kind.relocations")" -eq 6
done
