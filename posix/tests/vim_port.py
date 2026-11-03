#!/usr/bin/env python3
"""Exercise the private port compiler with real SDK/runtime and real LLD."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]


def main(configuration):
    driver = ROOT / "scripts/vim/cc.py"
    with tempfile.TemporaryDirectory(prefix="vim-compiler-", dir=ROOT / "out/checks/tmp") as name:
        directory = Path(name)
        source, output = directory / "main.c", directory / "main"
        source.write_text(
            "#if VALUE != 7\n#error C flags were lost\n#endif\n"
            "int main(void) { return 0; }\n"
        )
        subprocess.run([
            "python3", str(driver), str(configuration), "-D", "VALUE=7",
            "-v", "-std=gnu17", "--param", "max-inline-insns-single=1200",
            "-static", str(source), "-o", str(output),
        ], check=True)
        data = output.read_bytes()
        assert data[:4] == b"\x7fELF"
        assert struct.unpack_from("<HH", data, 16) == (2, 62)
        offset = struct.unpack_from("<Q", data, 32)[0]
        stride, count = struct.unpack_from("<HH", data, 54)
        segments = [struct.unpack_from("<II", data, offset + index * stride) for index in range(count)]
        assert any(kind == 1 for kind, _ in segments)
        assert all(kind != 3 for kind, _ in segments), "unexpected ELF interpreter"
        assert any(kind == 0x6474E551 and flags & 1 == 0 for kind, flags in segments)
        rejected = directory / "rejected"
        result = subprocess.run([
            "python3", str(driver), str(configuration), "-shared",
            str(source), "-o", str(rejected),
        ], capture_output=True, text=True)
        assert result.returncode != 0 and "unsupported" in result.stderr
        assert not rejected.exists()
    print("vim-port: PASS actual LLD source link, C flags, static ELF, NX stack and unsupported profile")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path, required=True)
    main(parser.parse_args().toolchain.resolve())
