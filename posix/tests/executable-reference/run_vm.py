#!/usr/bin/env python3
"""Observe a native signed fixture from coherent snapshots of a private KVM disk."""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'scripts'))
from testing.qmp import Qmp


def copy_partition(source, output, partition):
    """Copy a MiB-aligned Data partition only after the owner pauses and flushes it."""
    start, size = partition['start'], partition['size']
    if start < 0 or size <= 0 or start % 2048 or size % 2048:
        raise ValueError('Expected a nonempty MiB-aligned partition')
    # A bounded raw view preserves exact partition boundaries. Sparse output
    # avoids writing all 128 MiB of mostly empty Data at every observation.
    view = {'driver': 'raw', 'offset': start * 512, 'size': size * 512,
            'file': {'driver': 'qcow2',
                     'file': {'driver': 'file', 'filename': str(source.resolve())}}}
    subprocess.run(['qemu-img', 'convert', '-U', '-O', 'raw', '-S', '4096',
                    'json:' + json.dumps(view), str(output)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if output.stat().st_size != size * 512:
        raise RuntimeError('Partition capture has the wrong extent')


def run(image, directory, result_path, passed, failed, required, timeout):
    """Require complete guest result lines; boot, timeout or launcher exit is not success."""
    image = image.resolve(strict=True)
    if not image.is_file():
        raise ValueError('VM input must be a regular image file')
    directory = directory.resolve()
    if directory.exists() or not directory.is_relative_to((ROOT / 'out').resolve()):
        raise ValueError('Use a fresh VM directory below workspace out/')
    if (not re.fullmatch(r'/tmp/[A-Za-z0-9_.-]{1,128}', result_path)
            or result_path[5:] in ('.', '..')):
        raise ValueError('Result must be a single file under /tmp')
    if (not 1 <= timeout <= 3600 or not passed or not failed or passed == failed
            or any(character in passed + failed for character in '\0\r\n')):
        raise ValueError('Invalid timeout or result markers')
    layout = json.loads(subprocess.check_output(['sfdisk', '--json', str(image)]))
    partitions = [p for p in layout['partitiontable']['partitions']
                  if p['type'].lower() == '6d6f6368-694f-5300-8000-6d5061727402']
    if len(partitions) != 1:
        raise ValueError('Expected exactly one mochiOS Data partition')
    data = partitions[0]
    if data['start'] % 2048 or data['size'] % 2048:
        raise ValueError('Expected MiB-aligned Data partition')
    with open('/dev/kvm', 'rb+'):
        pass
    directory.mkdir(parents=True)
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                    '-b', str(image), str(directory / 'disk.qcow2')], check=True)
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.snakeoil.fd', directory / 'vars.fd')
    command = ['qemu-system-x86_64', '-machine', 'q35,accel=kvm,smm=on', '-cpu', 'host',
               '-m', '6G', '-smp', '2', '-rtc', 'base=utc,clock=vm', '-no-reboot',
               '-no-shutdown', '-boot', 'order=c,menu=off,strict=on',
               '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
               '-drive', 'if=pflash,format=raw,file=vars.fd',
               '-global', 'driver=cfi.pflash01,property=secure,value=on',
               '-drive', 'id=osdisk,if=none,format=qcow2,file=disk.qcow2',
               '-device', 'virtio-blk-pci,disable-modern=on,drive=osdisk,bootindex=1',
               '-object', 'rng-random,id=rng0,filename=/dev/urandom',
               '-device', 'virtio-rng-pci,rng=rng0', '-device', 'virtio-gpu-pci,disable-legacy=on',
               '-display', 'none', '-serial', 'file:serial.log', '-monitor', 'none',
               '-qmp', 'unix:qmp.sock,server=on,wait=off',
               '-gdb', 'unix:gdb.sock,server=on,wait=off']
    with image.open('rb') as source:
        image_digest = hashlib.file_digest(source, 'sha256').hexdigest()
    report = {'passed': False, 'image': str(image), 'image_sha256': image_digest, 'arguments': command,
              'required_lines': required, 'result_path': result_path}
    qmp = process = None
    started = time.monotonic()
    old_cwd = Path.cwd()
    try:
        os.chdir(directory)  # Keep the Unix socket name below the kernel path limit.
        with open('qemu.log', 'wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            while not Path('qmp.sock').exists():
                if process.poll() is not None or time.monotonic() - started > 20:
                    raise RuntimeError('QEMU did not start; inspect qemu.log')
                time.sleep(.1)
            qmp = Qmp(Path('qmp.sock'))
            if qmp.command('query-kvm') != {'enabled': True, 'present': True}:
                raise RuntimeError('KVM was not enabled')
            previous = None
            while time.monotonic() - started < timeout:
                if process.poll() is not None:
                    raise RuntimeError('QEMU exited before a verified result')
                with open('capture.lock', 'a+b') as guard:
                    fcntl.flock(guard, fcntl.LOCK_EX)
                    qmp.command('stop')
                    try:
                        if qmp.command('query-status')['status'] != 'paused':
                            raise RuntimeError('Could not pause VM for coherent capture')
                        flush = qmp.command('human-monitor-command', {'command-line': 'qemu-io osdisk "flush"'})
                        if flush.strip():
                            raise RuntimeError('Disk flush failed: ' + flush)
                        copy_partition(Path('disk.qcow2'), Path('data.snapshot.img'), data)
                        response = subprocess.run(['debugfs', '-R', 'cat ' + result_path,
                                                   'data.snapshot.img'], capture_output=True)
                        diagnostic = response.stderr.decode('utf-8', errors='replace')
                        errors = '\n'.join(line for line in diagnostic.splitlines()
                                           if not line.startswith('debugfs ')).strip()
                        if response.returncode or (errors and 'File not found by ext2_lookup' not in errors):
                            raise RuntimeError('Cannot inspect guest result: ' + errors)
                        text = response.stdout.decode('utf-8', errors='strict')
                    finally:
                        qmp.command('cont')
                if '\0' in text:
                    raise RuntimeError('Incoherent guest result contains NUL bytes')
                Path('guest-result.log').write_text(text)
                if text != previous:
                    print(f'[{time.monotonic()-started:.1f}s]\n{text}', flush=True)
                    previous = text
                lines = text.split('\n')[:-1]  # Ignore an in-progress final write.
                if any(line == failed or line.startswith((failed + ' ', failed + ':')) for line in lines):
                    raise RuntimeError('Guest fixture reported failure')
                if passed in lines:
                    if lines.count(passed) != 1 or not all(line in lines for line in required):
                        raise RuntimeError('Missing or duplicate guest evidence')
                    report['passed'] = True
                    report['result_sha256'] = hashlib.sha256(response.stdout).hexdigest()
                    return
                time.sleep(10)
            raise TimeoutError('Native fixture timed out; no success inferred')
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        if qmp is not None:
            qmp.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        report['elapsed_seconds'] = time.monotonic() - started
        (directory / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        os.chdir(old_cwd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--result', default='/tmp/executable-api-results.log')
    parser.add_argument('--pass-line', default='EXE-API PASS')
    parser.add_argument('--fail-line', default='EXE-API FAIL')
    parser.add_argument('--required-line', action='append', default=[])
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    run(args.image, args.directory, args.result, args.pass_line, args.fail_line,
        args.required_line, args.timeout)
