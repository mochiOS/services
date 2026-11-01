"""Exercise the real host clangDriver library and its mochiOS linker selection.

Source jobs use -###; only object-input jobs execute. Native frontend and
generated ELF execution are covered separately on mochiOS, never by a fallback.
"""

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


class ClangDriver(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clang-driver-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sdk = self.root / "SDK with spaces"
        self.bin = self.sdk / "bin"
        self.bin.mkdir(parents=True)
        self.clang = self.bin / "clang"
        shutil.copy2(INPUTS.driver, self.clang)
        (self.bin / "ld").symlink_to(INPUTS.ld)
        for name in (
            "lib/crt0.o", "lib/linker.ld", "lib/libmochi_user_newlib_runtime.a",
            "lib/libgcc.a", "sysroot/lib/libc.a", "sysroot/lib/libm.a",
        ):
            output = self.sdk / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.symlink_to(INPUTS.sdk / name)
        self.env = {key: value for key, value in os.environ.items()
                    if key not in ("MOCHIOS_SDK", "LIBRARY_PATH", "CCC_OVERRIDE_OPTIONS")}
        self.env.update(MOCHIOS_LLD=str(INPUTS.lld), MOCHIOS_MSIGN=str(INPUTS.msign))
        self.source = self.root / "main.c"
        self.source.write_text("int main(void) { return 37; }\n")

    def run_driver(self, *arguments, status=0):
        result = subprocess.run([str(self.clang), *map(str, arguments)],
                                env=self.env, cwd=self.root, capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        return result

    def jobs(self, *arguments, source=None):
        result = self.run_driver("-###", source or self.source, *arguments)
        jobs = [shlex.split(line) for line in result.stderr.splitlines()
                if line.lstrip().startswith('"')]
        self.assertTrue(jobs, result.stderr)
        return jobs

    def test_default_target_selects_common_driver_and_sdk_without_host_libraries(self):
        jobs = self.jobs("-o", "main")
        self.assertEqual(len(jobs), 2)
        cc1, link = jobs
        self.assertIn("x86_64-unknown-mochios", cc1)
        self.assertIn("-nostdsysteminc", cc1)
        self.assertIn("-disable-red-zone", cc1)
        self.assertIn(str(self.sdk / "sysroot/include"), cc1)
        self.assertEqual(Path(link[0]), self.bin / "ld")
        self.assertIn("--mochios-sdk=" + str(self.sdk), link)
        self.assertIn("--sysroot=" + str(self.sdk / "sysroot"), link)
        self.assertNotIn("-lc", link)
        self.assertFalse(any("crtbegin" in word or "crt1.o" in word for word in link))

    def test_compile_only_and_include_suppression(self):
        self.assertEqual(len(self.jobs("-c")), 1)
        cc1 = self.jobs("-c", "-nostdinc")[0]
        self.assertNotIn(str(self.sdk / "sysroot/include"), cc1)
        self.assertFalse(any(word.endswith("/include") for word in cc1))
        cc1 = self.jobs("-c", "-nostdlibinc")[0]
        self.assertNotIn(str(self.sdk / "sysroot/include"), cc1)
        self.assertTrue(any("lib/clang/18/include" in word for word in cc1))

    def test_explicit_sysroot_and_environment_sdk_have_distinct_roles(self):
        self.env["MOCHIOS_SDK"] = str(self.sdk)
        sysroot = self.root / "alternate headers"
        jobs = self.jobs("--sysroot=" + str(sysroot))
        self.assertIn(str(sysroot / "include"), jobs[0])
        self.assertIn("--sysroot=" + str(sysroot), jobs[1])
        self.assertIn("--mochios-sdk=" + str(self.sdk), jobs[1])
        del self.env["MOCHIOS_SDK"]
        external = self.root / "another SDK/sysroot"
        jobs = self.jobs("--sysroot=" + str(external))
        self.assertIn("--mochios-sdk=" + str(external.parent), jobs[1])
        jobs = self.jobs("--sysroot=" + str(external) + "/")
        self.assertIn("--mochios-sdk=" + str(external.parent), jobs[1])
        self.assertIn("--mochios-sdk=.", self.jobs("--sysroot=sysroot/")[1])

    def test_link_arguments_and_runtime_selection_reach_driver(self):
        library = str(self.root / "library path")
        link = self.jobs("-nostartfiles", "-nodefaultlibs", "-L", library,
                         "--rtlib=compiler-rt", "-Wl,--no-sign", "-Xlinker", "--gc-sections")[-1]
        for word in ("-nostartfiles", "-nodefaultlibs", "--compiler-runtime=compiler-rt",
                     "--no-sign", "--gc-sections"):
            self.assertIn(word, link)
        self.assertTrue(library in link or "-L" + library in link)
        self.assertIn("-nostdlib", self.jobs("-nostdlib")[-1])
        self.assertIn("-r", self.jobs("-r")[-1])

    def test_alternate_backend_and_unsupported_abi_are_rejected(self):
        self.assertEqual(Path(self.jobs("-fuse-ld=lld")[-1][0]), self.bin / "ld")
        self.run_driver("-###", self.source, "-fuse-ld=gold", status=1)
        self.run_driver("-###", self.source, "-m32", status=1)
        self.run_driver("-###", self.source, "--target=x86_64-unknown-mochios-macho", status=1)
        for triple in ("i386-unknown-mochios", "x86_64-unknown-mochios-gnux32",
                       "x86_64-unknown-mochios-macho"):
            self.run_driver("--target-defines", triple, status=1)
        self.run_driver("-###", self.source, "--rtlib=unknown", status=1)

    def test_cpp_uses_only_sdk_libcxx_and_respects_omission(self):
        jobs = self.jobs("--driver-mode=g++")
        self.assertIn(str(self.sdk / "sysroot/include/c++/v1"), jobs[0])
        for library in ("-lc++", "-lc++abi", "-lunwind"):
            self.assertIn(library, jobs[1])
        self.assertNotIn("-lc++", self.jobs("--driver-mode=g++", "-nostdlib++")[-1])
        self.assertNotIn("-lc++", self.jobs("--driver-mode=g++", "-r")[-1])
        self.run_driver("-###", self.source, "--driver-mode=g++", "-stdlib=libstdc++", status=1)

    def test_target_macros_and_lp64_abi_are_mochios_not_linux(self):
        result = self.run_driver("--target-defines", "x86_64-unknown-mochios")
        for definition in ("#define __mochios__ 1", "#define __unix__ 1", "#define __ELF__ 1"):
            self.assertIn(definition, result.stdout)
        self.assertIn("pointer-width=64 long-width=64", result.stdout)
        self.assertNotIn("__linux", result.stdout)
        self.assertNotIn("_REENTRANT", result.stdout)
        result = self.run_driver("--target-defines", "x86_64-unknown-mochios", "pthread")
        self.assertIn("#define _REENTRANT 1", result.stdout)
        result = self.run_driver("--target-defines", "x86_64-unknown-linux-gnu")
        self.assertIn("#define __linux__ 1", result.stdout)
        self.assertNotIn("__mochios__", result.stdout)

    def test_real_object_link_is_signed_and_link_failure_keeps_previous_output(self):
        object_file = self.root / "main.o"
        subprocess.run([str(INPUTS.cc), "--target=x86_64-unknown-none-elf", "-fno-pie",
                        "-mno-red-zone", "-c", str(self.source), "-o", str(object_file)], check=True)
        output = self.root / "main"
        self.run_driver(object_file, "-o", output)
        verified = subprocess.run([str(INPUTS.msign), "elf", "verify", str(output)],
                                  capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        previous = output.read_bytes()
        self.assertEqual(previous[:4], b"\x7fELF")
        self.source.write_text("extern int absent_symbol(void); int main(void) { return absent_symbol(); }\n")
        subprocess.run([str(INPUTS.cc), "--target=x86_64-unknown-none-elf", "-fno-pie",
                        "-c", str(self.source), "-o", str(object_file)], check=True)
        failure = self.run_driver(object_file, "-o", output, status=1)
        self.assertIn("absent_symbol", failure.stderr)
        self.assertEqual(output.read_bytes(), previous)
        self.assertFalse(list(self.root.glob(".mochios-ld-*")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)

    def input_path(value):
        # LLD's driver flavor depends on argv[0]; retain the ld.lld symlink name.
        path = Path(value).absolute()
        if not path.exists():
            raise argparse.ArgumentTypeError("input does not exist: " + str(path))
        return path

    for option in ("driver", "ld", "lld", "msign", "sdk", "cc"):
        parser.add_argument("--" + option, type=input_path, required=True)
    INPUTS = parser.parse_args()
    unittest.main(argv=[__file__], verbosity=2)
