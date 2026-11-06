#!/usr/bin/env python3
"""Build the public C ABI probe; consume an existing SDK/runtime read-only."""
import argparse
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(__doc__)
for name in ("sdk", "runtime", "reent", "ioctl", "signer", "lld", "out"):
    parser.add_argument("--" + name, required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
sdk = args.sdk.resolve()
commands = []


def run(command):
    command = list(map(str, command))
    commands.append(command)
    subprocess.run(command, check=True)


for name, is_root in (("libdlfcn387.so", False), ("root.so", True)):
    obj = out / (name + ".o")
    run(["clang", "--target=x86_64-unknown-none-elf", "-O2", "-fPIC",
         "-ffreestanding", "-fno-stack-protector", "-mno-red-zone", "-nostdlib",
         "-c", root / "services/posix/tests/support/dlfcn_library.c", "-o", obj,
         *(["-DROOT"] if is_root else [])])
    run([args.lld, "-flavor", "gnu", "-shared", "-z", "now", "-z", "relro",
         "-z", "noexecstack", "--hash-style=both", "-soname", name, obj,
         "-o", out / name, *(["-L", out, "-l:libdlfcn387.so"] if is_root else [])])
    if not is_root:
        (out / "unsigned.so").write_bytes((out / name).read_bytes())
    run([args.signer, "elf", "sign", out / name, "--adhoc"])

modified = bytearray((out / "libdlfcn387.so").read_bytes())
modified[0x100] ^= 1
(out / "tampered.so").write_bytes(modified)
(out / "risky.toml").write_text(
    "[package]\nid='local.risky.library'\nname='risky'\nversion='1'\n"
    "[[binary]]\npath='/tmp/risky.so'\nkind='library'\n"
    "requires=['input.keyboard.global']\n")
run([args.signer, "elf", "sign", out / "unsigned.so", "--adhoc", "--manifest",
     out / "risky.toml", "--output", out / "risky.so"])
run(["x86_64-elf-gcc", f"--sysroot={sdk}/sysroot", "-isystem",
     sdk / "sysroot/include", "-I", root / "user/libc-port/include", "-D__mochios__",
     "-O2", "-g0", "-fno-pie", "-mno-red-zone", "-static", "-nostdlib",
     "-nostartfiles", "-Wl,-T," + str(sdk / "lib/linker.ld"), "-Wl,-no-pie",
     "-Wl,-z,noexecstack", "-Wl,--start-group", sdk / "lib/crt0.o",
     root / "services/posix/tests/native_dlfcn.c", args.runtime, args.reent,
     args.ioctl, "-lc", "-lm", "-lgcc", "-Wl,--end-group", "-o", out / "native-dlfcn387"])
(out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
