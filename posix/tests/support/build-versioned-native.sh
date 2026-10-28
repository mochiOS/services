#!/usr/bin/env bash
# Consume the already built SDK and standalone runtime; never build the SDK.
set -eu
fixture_out=${1:?usage: build-versioned-native.sh output-directory}
fixture_support=services/posix/tests/support
mkdir -p "$fixture_out/good" "$fixture_out/bad" "$fixture_out/legacy"
sed 's/API_2/API_3/g' "$fixture_support/versioned_library.c" > "$fixture_out/bad/library.c"
sed 's/API_2/API_3/g' "$fixture_support/versioned_library.map" > "$fixture_out/bad/library.map"
for kind in good bad; do
  if test "$kind" = good; then
    fixture_source="$fixture_support/versioned_library.c"
    fixture_map="$fixture_support/versioned_library.map"
  else
    fixture_source="$fixture_out/bad/library.c"
    fixture_map="$fixture_out/bad/library.map"
  fi
  x86_64-elf-gcc -O2 -fPIC -ffreestanding -fno-stack-protector -nostdlib \
    -Wl,-shared,-z,noexecstack,-soname,libversions.so -Wl,--hash-style=both \
    -Wl,--version-script,"$fixture_map" -DVERSIONED_TLS -ftls-model=initial-exec \
    "$fixture_source" -o "$fixture_out/$kind/libversions.so"
done
printf '%s\n' 'int api_data=7; int api_call(int n){return n+7;}' > "$fixture_out/legacy/library.c"
x86_64-elf-gcc -O2 -fPIC -nostdlib -Wl,-shared,-z,noexecstack,-soname,libversions.so \
  "$fixture_out/legacy/library.c" -o "$fixture_out/legacy/libversions.so"
for kind in good preempt bad legacy; do
  fixture_link=good
  fixture_search=good
  fixture_flags=(-DVERSIONED_TLS)
  case "$kind" in
    preempt) fixture_flags+=(-DROOT_PREEMPTION);;
    bad) fixture_search=bad;;
    legacy) fixture_link=legacy; fixture_flags=(-DUNVERSIONED_REFERENCE);;
  esac
  x86_64-elf-gcc -O2 -fPIC -Wall -Wextra -Werror -I user/libc-port/include \
    -isystem out/newlib-port/sdk/sysroot/include --sysroot=out/newlib-port/sdk/sysroot \
    -Lout/newlib-port/sdk/sysroot/lib -nostdlib -nostartfiles -ftls-model=initial-exec \
    -Wl,-T,"$fixture_support/native_dynamic.ld",-no-pie,-z,noexecstack,--export-dynamic,--no-dynamic-linker \
    -Wl,-rpath,/tmp/symbol-versions-265/"$fixture_search",--enable-new-dtags \
    -o "$fixture_out/$kind.elf" "${fixture_flags[@]}" services/posix/tests/native_versioned_app.c \
    -L"$fixture_out/$fixture_link" -Wl,--no-as-needed -lversions -Wl,--start-group \
    out/newlib-port/sdk/lib/crt0.o \
    out/continuous-native-check/x86_64-unknown-mochios/release/libmochi_user_newlib_runtime.a \
    out/continuous-native-check/native-probes/newlib_reent.o -lc -lm -lgcc -Wl,--end-group
done
