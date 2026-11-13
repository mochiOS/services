"""Regress coherent-capture boundaries against the actual installed qemu-img."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from run_vm import copy_partition


@unittest.skipUnless(shutil.which('qemu-img'), 'qemu-img required')
class PartitionCapture(unittest.TestCase):
    def test_middle_partition_excludes_both_neighbours(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / 'source.raw'
            wanted = b'D' * (1024 * 1024)
            raw.write_bytes(b'A' * len(wanted) + wanted + b'Z' * len(wanted))
            disk, captured = root / 'disk.qcow2', root / 'captured.raw'
            subprocess.run(['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2',
                            str(raw), str(disk)], check=True)
            copy_partition(disk, captured, {'start': 2048, 'size': 2048})
            self.assertEqual(captured.read_bytes(), wanted)

    def test_invalid_extent_is_rejected_before_access(self):
        for partition in ({'start': 1, 'size': 2048}, {'start': 2048, 'size': 0},
                          {'start': -2048, 'size': 2048}):
            with self.subTest(partition=partition), self.assertRaises(ValueError):
                copy_partition(Path('missing'), Path('unused'), partition)


if __name__ == '__main__':
    unittest.main()
