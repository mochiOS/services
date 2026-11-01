#!/usr/bin/env python3
"""Exercise actual initial and incremental images, including debugfs failures."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SYNC = ROOT / "scripts/mmake/sync-ext2.py"


class ImageSymlinks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for name in ("mke2fs", "debugfs", "e2fsck", "fakeroot"):
            if shutil.which(name) is None:
                raise RuntimeError(f"required test tool is missing: {name}")

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='image symlink "test-')
        self.addCleanup(self.work.cleanup)
        self.directory = Path(self.work.name)
        self.stage = self.directory / "stage"
        self.stage.mkdir()
        self.image = self.directory / "image.ext2"
        self.state = self.image.with_suffix(self.image.suffix + ".state.json")

    def run_sync(self, mode="sync", *, success=True, environment=None):
        result = subprocess.run(
            [sys.executable, str(SYNC), mode, str(self.stage), str(self.image), str(self.state)],
            capture_output=True, text=True, env=environment,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def initial(self, kind="ext2"):
        with self.image.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024)
        result = subprocess.run(
            ["mke2fs", "-q", "-t", kind, "-b", "4096", "-d",
             str(self.stage), "-F", str(self.image)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.run_sync("record")

    def debug(self, command):
        result = subprocess.run(
            ["debugfs", "-R", command, str(self.image)], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        errors = [line for line in result.stderr.splitlines()
                  if line and not re.match(r"^debugfs [0-9]", line)]
        self.assertEqual(errors, [], result.stderr)
        return result.stdout

    def assert_link(self, name, target):
        metadata = self.debug("stat /" + name)
        self.assertIn("Type: symlink", metadata)
        if len(target.encode()) < 60:
            self.assertIn('Fast link dest: "' + target + '"', metadata)
        else:
            self.assertEqual(self.debug("cat /" + name), target)
        entry = json.loads(self.state.read_text())[name]
        self.assertEqual((entry["type"], entry["target"]), ("symlink", target))

    def assert_clean(self):
        result = subprocess.run(
            ["e2fsck", "-f", "-n", str(self.image)], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_initial_and_incremental_targets_are_literal_on_ext2_and_ext4(self):
        targets = [
            "plain", "../developer/bin/clang", "/system/developer/bin/clang",
            "missing", "../dir with spaces/file", 'a"b\\c', "é/日本語", "x" * 180,
        ]
        for kind in ("ext2", "ext4"):
            with self.subTest(kind=kind):
                for path in self.stage.iterdir():
                    path.unlink()
                (self.stage / "plain").write_text("payload\n")
                for index, target in enumerate(targets):
                    os.symlink(target, self.stage / f"link{index}")
                self.initial(kind)
                for index, target in enumerate(targets):
                    self.assert_link(f"link{index}", target)
                for index, target in enumerate(targets):
                    path = self.stage / f"link{index}"
                    path.unlink()
                    os.symlink(target + '";literal\\suffix', path)
                self.run_sync()
                for index, target in enumerate(targets):
                    self.assert_link(f"link{index}", target + '";literal\\suffix')
                self.assertEqual(self.debug("cat /plain"), "payload\n")
                self.assert_clean()

    def test_type_replacement_removes_children_before_replacing_directories(self):
        path = self.stage / "entry"
        path.write_text("original")
        self.initial()
        path.unlink()
        os.symlink("missing", path)
        self.run_sync()
        self.assert_link("entry", "missing")
        path.unlink()
        path.mkdir()
        (path / "child").write_text("nested")
        self.run_sync()
        self.assertEqual(self.debug("cat /entry/child"), "nested")
        (path / "child").unlink()
        path.rmdir()
        os.symlink("plain", path)
        self.run_sync()
        self.assert_link("entry", "plain")
        path.unlink()
        path.write_text("replacement")
        self.run_sync()
        self.assertEqual(self.debug("cat /entry"), "replacement")
        self.assertNotIn("entry/child", json.loads(self.state.read_text()))
        self.assert_clean()

    def test_directory_links_are_not_traversed_and_ownership_does_not_follow(self):
        outside = self.directory / "outside"
        outside.mkdir()
        private = outside / "private"
        private.write_text("outside stage")
        private.chmod(0o600)
        os.symlink(str(outside), self.stage / "directory")
        os.symlink("missing", self.stage / "owned")
        (self.stage / ".mochios-ownership").write_text("owned 123 456\n")
        self.initial()
        entries = json.loads(self.state.read_text())
        self.assertNotIn("directory/private", entries)
        self.assert_link("directory", str(outside))
        self.assertRegex(self.debug("stat /owned"), r"User:\s+123\s+Group:\s+456")
        self.assertEqual(private.read_text(), "outside stage")
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assert_clean()

    def test_unchanged_links_do_not_write_and_removed_links_disappear(self):
        os.symlink("missing", self.stage / "link")
        self.initial()
        before = hashlib.sha256(self.image.read_bytes()).digest()
        self.run_sync()
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).digest(), before)
        (self.stage / "link").unlink()
        self.run_sync()
        self.assertNotIn("link", json.loads(self.state.read_text()))
        result = subprocess.run(
            ["debugfs", "-R", "stat /link", str(self.image)], capture_output=True, text=True,
        )
        self.assertIn("File not found", result.stderr)
        self.assert_clean()

    def test_unrepresentable_target_cannot_inject_another_debugfs_command(self):
        (self.stage / "plain").write_text("keep")
        self.initial()
        before_state = self.state.read_bytes()
        before_image = hashlib.sha256(self.image.read_bytes()).digest()
        os.symlink('missing"\nrm /plain\n"', self.stage / "link")
        result = self.run_sync(success=False)
        self.assertIn("line break", result.stderr)
        self.assertEqual(self.state.read_bytes(), before_state)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).digest(), before_image)

    def test_debugfs_error_with_zero_exit_does_not_advance_state(self):
        self.initial()
        os.symlink("missing", self.stage / "link")
        tools = self.directory / "tools"
        tools.mkdir()
        fake = tools / "debugfs"
        fake.write_text("#!/bin/sh\nprintf 'symlink: injected write failure\\n' >&2\nexit 0\n")
        fake.chmod(0o755)
        environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"])
        result = self.run_sync(success=False, environment=environment)
        self.assertIn("injected write failure", result.stderr)
        self.assertFalse(self.state.exists())
        # The normal image command must rebuild, rather than replay a partial
        # update from metadata which no longer describes the image.
        config = self.directory / "config"
        config.write_text(
            "IMAGE_DISK_SIZE_MB=24\nIMAGE_ESP_SIZE_MB=4\nIMAGE_DATA_SIZE_MB=2\n"
        )
        result = subprocess.run(
            [str(ROOT / "scripts/mmake/make-ext2-image.sh"), str(self.stage),
             str(self.image), "rootfs", str(config)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_link("link", "missing")
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
