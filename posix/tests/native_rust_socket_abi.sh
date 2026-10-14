#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 ]]; then
    echo "usage: $0 <target-rustc> <target-json> <libc-rmeta> <core-rmeta> <output-rmeta>" >&2
    exit 2
fi

probe_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUSTC_BOOTSTRAP=1 "$1" \
    --crate-name native_rust_socket_abi --edition=2021 \
    --crate-type=lib --emit=metadata -Cpanic=abort \
    --target "$2" -Zunstable-options \
    --extern "libc=$3" --extern "core=$4" \
    -L "dependency=$(dirname -- "$3")" \
    "$probe_dir/native_rust_socket_abi.inc" -o "$5"
echo "native-rust-socket-abi: PASS public target types, constants, layout, CMSG helpers and function signatures"
