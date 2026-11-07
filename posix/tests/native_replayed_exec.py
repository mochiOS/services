#!/usr/bin/env python3
"""Stage a normally authenticated native exec regression application, offline.

The caller must compose the returned System files into a disposable development
image using its normal built-in package verification and boot-module tooling.
This script neither changes a running OS nor publishes an SDK.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def run(*args):
    subprocess.run(list(map(str, args)), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--msign', type=Path, required=True)
    parser.add_argument('--capability-binary', type=Path, required=True)
    args = parser.parse_args()
    sources = Path(__file__).resolve().parent
    services = sources.parent.parent
    output = args.output.resolve()
    if output.exists():
        parser.error('Choose a fresh output directory')
    sdk = args.sdk.resolve()
    cc = sdk / 'bin/mochios-cc'
    for file in [cc, args.msign, args.capability_binary]:
        if not file.is_file():
            parser.error('Missing input: ' + str(file))
    stage = output / 'stage'
    bundle = stage / 'system/applications/ExecTest.app'
    binaries = stage / 'system/bin'
    libraries = stage / 'system/libraries/exec-test'
    for directory in [bundle, binaries, libraries]:
        directory.mkdir(parents=True, exist_ok=True)
    library_source = output / 'library.c'
    library_source.write_text('int exec_answer(void) { return 42; }\n')
    run(cc, library_source, '-shared', '-fPIC', '-Wl,-soname,libexecprobe.so',
        '-o', libraries / 'libexecprobe.so')
    for name, extra in [('exec-child', []), ('exec-extra', ['-DANSWER=43'])]:
        run(cc, sources / 'native_replayed_child.c', *extra, '-L' + str(libraries),
            '-lexecprobe', '-o', binaries / name)
    run(cc, sources / 'native_replayed_exec.c', '-o', bundle / 'entry.elf')
    # Preseed only the disposable Data image. File-copy throughput is not an
    # exec prerequisite; the guest still opens and unlinks the actual file.
    temporary = output / 'data/tmp/exec-test'
    temporary.mkdir(parents=True)
    temporary.chmod(0o777)  # Private fixture directory; keep the OS /tmp sticky bit.
    shutil.copyfile(binaries / 'exec-child', temporary / 'exec-pinned')
    tampered = bytearray((binaries / 'exec-child').read_bytes())
    tampered[-1] ^= 1
    (temporary / 'exec-tampered').write_bytes(tampered)
    shutil.copyfile(libraries / 'libexecprobe.so', temporary / 'libexecprobe.so')
    for name in ['exec-pinned', 'exec-tampered']:
        (temporary / name).chmod(0o755)
    capabilities = ['process.spawn', 'fs.read.all', 'fs.write.tmp', 'ipc.client',
                    'ipc.server', 'system.random.read', 'system.time.read']
    manifest = '''format = 1
[package]
provenance = "built-in"
id = "org.mochios.sdk.exec-test"
name = "Exec Test"
version = "0.1.0"
vendor = "mochiOS development fixture"
kind = "application"
architecture = "x86_64"
abi = "mochios-1"
[application]
entry = "entry.elf"
'''
    for path, kind, required in [
        ('/system/applications/ExecTest.app/entry.elf', 'application', capabilities),
        ('/system/bin/exec-child', 'application', capabilities),
        ('/system/bin/exec-extra', 'application', capabilities + ['net.connect']),
        ('/system/libraries/exec-test/libexecprobe.so', 'library', []),
    ]:
        (stage / path[1:]).chmod(0o755 if kind == 'application' else 0o644)
        manifest += ('\n[[binary]]\npath = ' + json.dumps(path) + '\nkind = '
                     + json.dumps(kind) + '\nrequires = ' + json.dumps(required) + '\n')
    source_manifest = output / 'manifest.toml'
    source_manifest.write_text(manifest)
    (bundle / 'manifest.toml').write_text(manifest)

    def bind(manifest, name):
        directory = stage / 'system/packages' / name
        directory.mkdir(parents=True)
        run(args.msign, 'package', 'bind-built-in', manifest, '--rootfs', stage,
            '--output', directory / 'manifest.toml')
        run(args.msign, 'package', 'built-in-record', directory / 'manifest.toml',
            '--output', directory / 'verification.bin')

    bind(source_manifest, 'exec-test')
    broker = stage / 'system/services/capability.service'
    broker.parent.mkdir(parents=True)
    shutil.copyfile(args.capability_binary, broker)
    broker.chmod(0o755)
    bind(services / 'capability/manifest.toml', 'capability')
    # Existing declarative session setup launches the normal application. Its
    # intentionally missing completion requirement keeps this disposable test repeatable.
    startup = stage / 'system/setup/session-startup.json'
    startup.parent.mkdir(parents=True)
    startup.write_text(json.dumps({'format': 1, 'rules': [{
        'handler': 'org.mochios.sdk.exec-test',
        'requirements': '/system/applications/ExecTest.app/setup.json'}]}) + '\n')
    (bundle / 'setup.json').write_text(json.dumps({'format': 1, 'applications': [
        {'bundle_id': 'org.mochios.sdk.test-missing'}]}) + '\n')
    # Evidence deliberately contains digests, never workstation paths.
    files = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(stage.rglob('*')) if p.is_file()}
    data_files = {str(p.relative_to(output / 'data')): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted((output / 'data').rglob('*')) if p.is_file()}
    (output / 'inputs.json').write_text(json.dumps(
        {'format': 1, 'files': files, 'data_files': data_files}, indent=2) + '\n')
    print('Development fixture staged:', stage)


if __name__ == '__main__':
    main()
