#!/usr/bin/env bash
set -euo pipefail

# Prepare an isolated disk for the existing KVM runner; never edit the release
# artifact or the runner configuration. Binder's automatic launch runs the probe.
tests=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$tests/../../.." && pwd)
sdk=$root/out/newlib-port/sdk
artifact=$root/out/artifacts/disk.img
msign=$root/out/mmake/host-tools/release/msign
for command in dd debugfs e2fsck cmp; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done
for input in "$artifact" "$sdk/bin/mochios-cc" "$msign"; do
    [[ -f $input ]] || { echo "missing input: $input" >&2; exit 1; }
done
source "$root/.config"
mkdir -p "$root/out/posix-host-check"
fixture=$(mktemp -d "$root/out/posix-host-check/native-pager.XXXXXX")
echo "native pager fixture retained at $fixture" >&2
"$sdk/bin/mochios-cc" -Wall -Wextra -Werror -O2 \
    "$tests/file_backed_mapping.c" -o "$fixture/probe.elf"
"$msign" package built-in-record "$tests/native-pager-manifest.toml" \
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
replace "$fixture/probe.elf" /system/applications/Binder.app/entry.elf
debugfs -w -R 'set_inode_field /system/applications/Binder.app/entry.elf mode 0100755' \
    "$fixture/rootfs.img" >/dev/null 2>&1
replace "$tests/native-pager-manifest.toml" /system/packages/binder/manifest.toml
replace "$fixture/verification.bin" /system/packages/binder/verification.bin
e2fsck -fn "$fixture/rootfs.img" >&2
dd if="$fixture/rootfs.img" of="$fixture/disk.img" bs=512 seek="$start" \
    conv=notrunc status=none
printf '%s\n' "$fixture/disk.img"
