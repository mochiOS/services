#!/usr/bin/env python3
"""Build the opt-in native fixture without replacing production service binaries."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def build(metadata, target_directory):
    """Consume generic app SDK metadata and isolate feature-specific Cargo output."""
    root = Path(__file__).resolve().parents[4]
    sdk = json.loads(metadata.read_text())
    if sdk.get('format') != 1:
        raise ValueError('Unsupported app SDK metadata')
    target_directory = target_directory.resolve()
    if target_directory == Path(sdk['target_dir']).resolve():
        raise ValueError('Fixture output must differ from the production target directory')
    environment = os.environ.copy()
    environment.update(sdk['versions'])
    environment.update(sdk['fonts'])
    environment.update(RUSTC=sdk['rustc'], RUSTDOC=sdk['rustdoc'],
                       CARGO_ENCODED_RUSTFLAGS='\x1f'.join(sdk['rustflags']))
    environment.pop('RUSTFLAGS', None)
    command = [sdk['cargo'], 'build', '--offline', '-Z',
               'build-std=std,panic_abort,compiler_builtins', '-Z', 'json-target-spec',
               '--release', '--target', sdk['target'], '--target-dir', str(target_directory)]
    for config in sdk['cargo_config']:
        command += ['--config', config]
    for manifest, selection in [
        (root / 'services/Cargo.toml', ['--package', 'service-manager', '--package', 'capability',
         '--package', 'filesystem-service', '--package', 'posix-service',
         '--package', 'user-service', '--package', 'logger', '--bins',
         '--features', 'service-manager/native-executable-reference-probe']),
        (Path(__file__).with_name('Cargo.toml'), ['--bins']),
    ]:
        subprocess.run(command + ['--manifest-path', str(manifest)] + selection,
                       cwd=root, env=environment, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-metadata', type=Path, required=True)
    parser.add_argument('--target-directory', type=Path, required=True)
    args = parser.parse_args()
    build(args.sdk_metadata, args.target_directory)
