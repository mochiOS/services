#!/usr/bin/env bash
set -euo pipefail

# Prepare an isolated disk for the existing KVM runner; never edit the release
# artifact or the runner configuration. Binder's automatic launch runs the probe
# by default. NATIVE_PROBE_ROLE=input isolates System I/O before dictionary
# parsing; its successful exit intentionally does not publish input readiness.
# NATIVE_PROBE_ROLE=heap exercises concurrent anonymous page population instead.
tests=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$tests/../../.." && pwd)
sdk=$root/out/newlib-port/sdk
artifact=$root/out/artifacts/disk.img
msign=$root/out/mmake/host-tools/release/msign
case ${NATIVE_PROBE_ROLE:-binder} in
    binder)
        probe_source=$tests/file_backed_mapping.c
        probe_manifest=$tests/native-pager-manifest.toml
        probe_entry=/system/applications/Binder.app/entry.elf
        probe_package=/system/packages/binder
        ;;
    input)
        probe_source=$tests/native_system_read.c
        probe_manifest=$tests/native-system-read-manifest.toml
        probe_entry=/system/services/input.service
        probe_package=/system/packages/input
        ;;
    heap)
        probe_source=$tests/heap_mapping.c
        probe_manifest=$tests/native-heap-manifest.toml
        probe_entry=/system/services/input.service
        probe_package=/system/packages/input
        ;;
    *) echo "unsupported native probe role" >&2; exit 1 ;;
esac
for command in dd debugfs e2fsck cmp; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done
for input in "$artifact" "$sdk/bin/mochios-cc" "$msign"; do
    [[ -f $input ]] || { echo "missing input: $input" >&2; exit 1; }
done
if [[ -n ${FILESYSTEM_SERVICE_BINARY:-} && ! -f $FILESYSTEM_SERVICE_BINARY ]]; then
    echo "missing filesystem service binary: $FILESYSTEM_SERVICE_BINARY" >&2
    exit 1
fi
source "$root/.config"
mkdir -p "$root/out/posix-host-check"
fixture=$(mktemp -d "$root/out/posix-host-check/native-pager.XXXXXX")
echo "native pager fixture retained at $fixture" >&2
"$sdk/bin/mochios-cc" -Wall -Wextra -Werror -O2 \
    "$probe_source" -o "$fixture/probe.elf"
"$msign" package built-in-record "$probe_manifest" \
    --output "$fixture/verification.bin"
cp --reflink=auto --sparse=always "$artifact" "$fixture/disk.img"
start=$((2048 + IMAGE_ESP_SIZE_MB * 2048))
sectors=$(((IMAGE_DISK_SIZE_MB - IMAGE_ESP_SIZE_MB - IMAGE_DATA_SIZE_MB - 2) * 2048))
dd if="$artifact" of="$fixture/rootfs.img" bs=512 skip="$start" \
    count="$sectors" conv=sparse status=none
replace() {
    local source=$1 destination=$2
    debugfs -w -R "rm $destination" "$fixture/rootfs.img" >/dev/null 2>&1
    debugfs -w -R "write $source $destination" "$fixture/rootfs.img" >/dev/null 2>&1
    debugfs -R "dump $destination $fixture/installed" "$fixture/rootfs.img" >/dev/null 2>&1
    cmp "$source" "$fixture/installed"
}
replace "$fixture/probe.elf" "$probe_entry"
debugfs -w -R "set_inode_field $probe_entry mode 0100755" \
    "$fixture/rootfs.img" >/dev/null 2>&1
replace "$probe_manifest" "$probe_package/manifest.toml"
replace "$fixture/verification.bin" "$probe_package/verification.bin"
if [[ -n ${FILESYSTEM_SERVICE_BINARY:-} ]]; then
    replace "$FILESYSTEM_SERVICE_BINARY" /system/services/filesystem.service
    debugfs -w -R 'set_inode_field /system/services/filesystem.service mode 0100755' \
        "$fixture/rootfs.img" >/dev/null 2>&1
fi
e2fsck -fn "$fixture/rootfs.img" >&2
dd if="$fixture/rootfs.img" of="$fixture/disk.img" bs=512 seek="$start" \
    conv=notrunc status=none
printf '%s\n' "$fixture/disk.img"
