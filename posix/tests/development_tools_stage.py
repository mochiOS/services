#!/usr/bin/env python3
"""Verify installation of supplied inputs without generating or changing an SDK."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
STAGER = ROOT / "scripts/mmake/stage-development-tools.py"


def elf(machine=62, interpreter=False):
    count = 2 if interpreter else 1
    data = bytearray(64 + count * 56)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, machine, 1, 0x400000,
                     64, 0, 0, 64, 56, count, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000,
                     len(data), len(data), 4096)
    if interpreter:
        struct.pack_into("<I", data, 120, 3)
    return data


class DevelopmentTools(unittest.TestCase):
    def stager(self):
        spec = importlib.util.spec_from_file_location("development_stager", STAGER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="development stage-")
        self.addCleanup(self.work.cleanup)
        self.directory = Path(self.work.name)
        self.sdk = self.directory / "sdk"
        self.llvm = self.directory / "llvm"
        self.tools = self.directory / "tools"
        self.stage = self.directory / "rootfs"
        self.files = {
            self.sdk / name: ("supplied " + name).encode()
            for name in (
                "lib/crt0.o", "lib/linker.ld", "lib/libmochi_user_newlib_runtime.a",
                "lib/libgcc.a", "sysroot/lib/libc.a", "sysroot/lib/libm.a",
                "sysroot/include/stdio.h",
            )
        }
        self.files[self.llvm / "lib/clang/18/include/stddef.h"] = b"resource header"
        for path in (self.llvm / "bin/clang-18", self.llvm / "bin/lld",
                     self.tools / "ld", self.tools / "msign"):
            self.files[path] = elf()
        for path, content in self.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def run_stage(self, success=True, umask=-1):
        result = subprocess.run(
            [sys.executable, str(STAGER), str(self.stage), "--sdk", str(self.sdk),
             "--llvm", str(self.llvm), "--rust-tools", str(self.tools)],
            capture_output=True, text=True, umask=umask,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)
        return result

    def snapshot(self):
        return {str(path): (hashlib.sha256(path.read_bytes()).digest(),
                            path.stat().st_mode & 0o777) for path in self.files}

    def test_layout_preserves_supplied_inputs_and_aliases_resolve_inside_sdk(self):
        before = self.snapshot()
        self.run_stage(umask=0o077)
        prefix = self.stage / "system/developer"
        self.assertEqual((prefix / "lib/linker.ld").read_bytes(),
                         (self.sdk / "lib/linker.ld").read_bytes())
        self.assertEqual((prefix / "sysroot/include/stdio.h").read_bytes(),
                         (self.sdk / "sysroot/include/stdio.h").read_bytes())
        for name in ("clang", "ld.lld", "ld", "msign"):
            alias = self.stage / "system/bin" / name
            target = prefix / "bin" / name
            self.assertTrue(alias.is_symlink())
            self.assertEqual(os.readlink(alias), "../developer/bin/" + name)
            self.assertEqual(alias.resolve(), target.resolve())
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            self.assertEqual(target.read_bytes(), elf())
        self.assertFalse((prefix / "manifest.toml").exists())
        package = self.stage / "system/packages/development-tools"
        declaration = package / "manifest.toml"
        metadata = tomllib.loads(declaration.read_text())
        self.assertEqual(metadata["package"]["id"], "org.mochios.development-tools")
        self.assertEqual(metadata["package"]["kind"], "binary")
        self.assertEqual(package.stat().st_mode & 0o777, 0o755)
        self.assertEqual(declaration.stat().st_mode & 0o777, 0o644)
        self.assertFalse((package / "verification.bin").exists())
        self.assertEqual(len(metadata["binary"]), 4)
        files = {entry["id"]: entry for entry in metadata["file"]}
        for binary in metadata["binary"]:
            entry = files[binary["file"]]
            name = Path(binary["path"]).name
            self.assertEqual(binary["path"], "/system/developer/bin/" + name)
            self.assertEqual(entry["path"], binary["path"])
            self.assertEqual(entry["digest"], "sha256:" + hashlib.sha256(elf()).hexdigest())
            self.assertEqual(entry["size"], len(elf()))
            self.assertEqual(entry["mode"], "0755")
            self.assertEqual(binary["kind"], "application")
            self.assertEqual(set(binary["requires"]), {
                "fs.read.all", "fs.write.tmp", "fs.write.user", "ipc.client",
                "ipc.server", "process.spawn", "system.random.read",
            })
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list((self.stage / "system").glob(".developer-*")), [])
        for directory in (prefix, self.stage / "system", self.stage / "system/bin",
                          *(p for p in prefix.rglob("*") if p.is_dir())):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)

    def test_missing_empty_and_non_native_tools_fail_before_publishing(self):
        path = self.tools / "ld"
        for content in (b"", b"#!/bin/sh\n", elf(machine=183), elf(interpreter=True)):
            with self.subTest(content=content[:20]):
                path.write_bytes(content)
                result = self.run_stage(False)
                self.assertIn("development tools:", result.stderr)
                self.assertFalse(self.stage.exists())
        path.unlink()
        self.assertIn("missing or empty", self.run_stage(False).stderr)
        self.assertFalse(self.stage.exists())

    def test_sdk_manifest_selects_builtins_and_is_preserved_without_rewriting(self):
        manifest = self.sdk / "manifest.toml"
        content = 'version = "supplied-version"\narchitecture = "x86_64"\ncompiler_runtime = "compiler-rt"\n'
        manifest.write_text(content)
        (self.sdk / "lib/libgcc.a").unlink()
        builtins = self.sdk / "lib/libclang_rt.builtins-x86_64.a"
        builtins.write_bytes(b"supplied builtins")
        self.run_stage()
        prefix = self.stage / "system/developer"
        self.assertEqual((prefix / "manifest.toml").read_text(), content)
        self.assertEqual(manifest.read_text(), content)
        self.assertEqual((prefix / "lib/libclang_rt.builtins-x86_64.a").read_bytes(),
                         b"supplied builtins")
        self.assertFalse((prefix / "lib/libgcc.a").exists())

    def test_invalid_manifest_or_missing_runtime_does_not_publish(self):
        manifest = self.sdk / "manifest.toml"
        for content in ('architecture = "aarch64"\n', 'compiler_runtime = "unknown"\n',
                        'compiler_runtime = "compiler-rt"\n', 'compiler_runtime = []\n',
                        'invalid = ['):
            with self.subTest(content=content):
                manifest.write_text(content)
                self.run_stage(False)
                self.assertFalse(self.stage.exists())

    def test_conflicts_and_header_links_cannot_replace_unrelated_content(self):
        bin_directory = self.stage / "system/bin"
        bin_directory.mkdir(parents=True)
        existing = bin_directory / "ld"
        existing.write_text("keep")
        self.assertIn("refusing to replace", self.run_stage(False).stderr)
        self.assertEqual(existing.read_text(), "keep")
        self.assertFalse((self.stage / "system/developer").exists())
        existing.unlink()
        private = self.directory / "private"
        private.write_text("not an SDK header")
        os.symlink(private, self.sdk / "sysroot/include/escaped.h")
        self.assertIn("escapes", self.run_stage(False).stderr)
        self.assertEqual(private.read_text(), "not an SDK header")
        self.assertFalse((self.stage / "system/developer").exists())

    def test_package_collision_is_rejected_without_touching_existing_files(self):
        package = self.stage / "system/packages/development-tools"
        package.mkdir(parents=True)
        marker = package / "manifest.toml"
        marker.write_text("existing package")
        self.assertIn("refusing to replace", self.run_stage(False).stderr)
        self.assertEqual(marker.read_text(), "existing package")
        self.assertFalse((self.stage / "system/developer").exists())
        self.assertFalse((self.stage / "system/bin/clang").exists())

    def test_alias_failure_rolls_back_sdk_package_and_only_its_own_links(self):
        module = self.stager()
        unrelated = self.stage / "system/packages/unrelated/keep"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("keep")
        before = self.snapshot()
        symlink = Path.symlink_to

        def fail_second(path, target, *args, **kwargs):
            if path.name == "ld.lld":
                raise OSError("injected alias failure")
            return symlink(path, target, *args, **kwargs)

        with patch.object(Path, "symlink_to", fail_second):
            with self.assertRaisesRegex(OSError, "injected alias failure"):
                module.stage_tools(self.stage, self.sdk, self.llvm, self.tools)
        self.assertFalse((self.stage / "system/developer").exists())
        self.assertFalse((self.stage / "system/packages/development-tools").exists())
        for name in module.TOOLS:
            self.assertFalse(os.path.lexists(self.stage / "system/bin" / name))
        self.assertEqual(unrelated.read_text(), "keep")
        self.assertEqual(self.snapshot(), before)

    def test_manifest_measures_published_bytes_including_non_loaded_trailer(self):
        module = self.stager()
        copy = module.shutil.copyfile
        before = self.snapshot()

        def altered_copy(source, destination, *args, **kwargs):
            result = copy(source, destination, *args, **kwargs)
            destination = Path(destination)
            if destination.parent.name == "bin":
                destination.write_bytes(destination.read_bytes() + b"copied trailer")
            return result

        with patch.object(module.shutil, "copyfile", altered_copy):
            module.stage_tools(self.stage, self.sdk, self.llvm, self.tools)
        metadata = tomllib.loads((self.stage / "system/packages/development-tools/manifest.toml").read_text())
        for entry in metadata["file"]:
            published = self.stage / entry["path"].lstrip("/")
            content = published.read_bytes()
            self.assertTrue(content.endswith(b"copied trailer"))
            self.assertEqual(entry["size"], len(content))
            self.assertEqual(entry["digest"], "sha256:" + hashlib.sha256(content).hexdigest())
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
