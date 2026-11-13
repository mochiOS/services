#!/usr/bin/env python3
"""Assemble a private signed native fixture using the ordinary OS image tools."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys


def assemble(output, native_directory, overlay=None, system_libraries=False):
    """Create a fresh file-backed A/B image; never modify normal images or disks."""
    root = Path(__file__).resolve().parents[4]
    output = output.resolve()
    if not output.is_relative_to((root / 'out').resolve()) or output.exists():
        raise ValueError('Use a new directory below the workspace out/ directory')
    normal = root / 'out/rust-std/target/x86_64-unknown-mochios/release'
    tools = root / 'out/mmake'
    msign = tools / 'host-tools/release/msign'
    stage = output / 'image/rootfs'
    stage.mkdir(parents=True)

    def run(*command):
        step = command[1] if str(command[0]) in ('bash', sys.executable) else command[0]
        print('Native image step:', Path(step).name, flush=True)
        subprocess.run([str(part) for part in command], cwd=root, check=True)

    def install(source, target, mode=0o644):
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(mode)

    for directory in ('bin', 'applications', 'libraries', 'home', 'var/lib/accounts',
                      'var/lib/packages', 'var/lib/security', 'var/log/services',
                      'var/config/account', 'system/services', 'system/packages', 'tmp'):
        (stage / directory).mkdir(parents=True, exist_ok=True)
    (stage / 'tmp').chmod(0o1777)
    shutil.copytree(root / 'resources/system', stage / 'system', dirs_exist_ok=True)
    shutil.copytree(root / 'resources/libraries', stage / 'system/libraries', dirs_exist_ok=True)
    shutil.rmtree(stage / 'system/users')
    (stage / 'system/.installed').write_text('format=1\n')
    # Use the existing development-account fixture, never a synthetic session.
    if 'DEVELOPMENT_DEFAULT_ACCOUNT=y' not in (root / '.config').read_text().splitlines():
        raise ValueError('This fixture requires the existing development-account configuration')
    install(root / 'scripts/mmake/development-users.db', stage / 'var/lib/accounts/users.db', 0o600)
    (stage / 'var/config/account/settings.conf').write_text('auto_login=true\nauto_login_user=testuser\n')
    owners = []
    for user, uid in [('root', 0), ('testuser', 1000)]:
        for suffix in ('', 'Desktop', 'Documents', 'Downloads', 'Movies', 'Music', 'Pictures'):
            relative = Path('home') / user / suffix
            (stage / relative).mkdir(parents=True, exist_ok=True)
            (stage / relative).chmod(0o700)
            owners.append(f'{relative} {uid} {uid}\n')
    (stage / '.mochios-ownership').write_text(''.join(owners))

    for package, binary, destination in [
        ('capability', 'capability', 'capability.service'),
        ('filesystem', 'filesystem-service', 'filesystem.service'),
        ('posix', 'posix-service', 'posix.service'),
        ('user', 'user-service', 'user.service'),
        ('logger', 'logger', 'logger.service'),
        ('service-manager', 'service-manager', 'service-manager.service'),
        ('signature', 'signature', 'signature.service'),
        ('package', 'package', 'package.service'),
        ('workspace', 'workspace-service', 'workspace.service'),
        ('secure-ui', 'secure-ui', 'secure-ui.service'),
        ('input', 'input', 'input.service'),
        ('compositor', 'compositor', 'compositor.service'),
        ('drivers', 'drivers', 'drivers.service'),
    ]:
        directory = native_directory if package in {'capability', 'filesystem', 'posix', 'user', 'logger', 'service-manager'} else normal
        install(directory / binary, stage / 'system/services' / destination, 0o755)
        bound = stage / 'system/packages' / package
        bound.mkdir(parents=True)
        run(msign, 'package', 'bind-built-in', root / 'services' / package / 'manifest.toml',
            '--rootfs', stage, '--output', bound / 'manifest.toml')
        run(msign, 'package', 'built-in-record', bound / 'manifest.toml',
            '--output', bound / 'verification.bin')
    # Capability's immutable trusted-role index authenticates these real
    # standard images even when the fixture does not launch the desktop.
    for name, binary, source, destination in [
        ('msh', 'msh', root / 'binaries/msh', stage / 'system/bin/msh'),
        ('terminal', 'terminal', root / 'applications/terminal',
         stage / 'system/applications/Terminal.app/entry.elf'),
    ]:
        install(normal / binary, destination, 0o755)
        if name == 'terminal':
            install(source / 'appicon.png', destination.with_name('appicon.png'))
        bound = stage / 'system/packages' / name
        bound.mkdir(parents=True)
        run(msign, 'package', 'bind-built-in', source / 'manifest.toml',
            '--rootfs', stage, '--output', bound / 'manifest.toml')
        run(msign, 'package', 'built-in-record', bound / 'manifest.toml',
            '--output', bound / 'verification.bin')
    run(sys.executable, Path(__file__).with_name('stage.py'), '--stage', stage,
        '--sdk', root / 'out/newlib-port/sdk', '--native-directory', native_directory,
        '--msign', msign)
    if system_libraries:
        run(sys.executable, root / 'scripts/mmake/stage-system-libraries.py',
            '--root', root, '--catalog', root / 'build/system-libraries.toml',
            '--stage', stage, '--msign', msign)
        shutil.copytree(root / 'libraries/fonts/out/fonts', stage / 'system/libraries/fonts',
                        dirs_exist_ok=True)
    if overlay is not None:
        shutil.copytree(overlay, stage, dirs_exist_ok=True)
    for name in ('BOOTX64.EFI', 'kernel.elf', 'kernel.meta'):
        install(tools / 'components' / name, output / 'components' / name)
    shutil.copytree(tools / 'cexts/disk.cext', output / 'cexts/disk.cext')
    scripts = root / 'scripts/mmake'
    run('bash', scripts / 'make-ext2-image.sh', stage, output / 'image/rootfs.img',
        'rootfs', root / '.config')
    run('bash', scripts / 'stage-initfs.sh', root, output)
    run('bash', scripts / 'make-ext2-image.sh', output / 'image/initfs',
        output / 'image/initfs.img', 'initfs', root / '.config')
    run('bash', scripts / 'make-ab-esp-image.sh', root, output)
    run('bash', scripts / 'build-ab-layout-image.sh', root, output,
        tools / 'components/boot-selection-seed', tools / 'components/system-image-sign',
        tools / 'components/system-slot-image')
    print('Private signed native fixture:', output / 'image/ab-layout.img', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-directory', type=Path, required=True)
    parser.add_argument('--overlay', type=Path)
    parser.add_argument('--system-libraries', action='store_true')
    args = parser.parse_args()
    assemble(args.output, args.native_directory.resolve(), args.overlay, args.system_libraries)
