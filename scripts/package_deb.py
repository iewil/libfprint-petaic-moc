#!/usr/bin/env python3
"""Create a Linux Mint 22/Ubuntu 24.04 amd64 install package from a tested build."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'libfprint-petaic-moc'
LIBRARY = ROOT / 'build/native-stage/opt/weact-fingerprint/lib/libfprint-2.so.2.0.0'
MANIFEST = ROOT / 'build/native-production/petaic-build-manifest.json'
CERT_HASHES = {
    'root.der': '4c25971e3bdde59d178f7a5ef62561e9e88edd93c274ddaa522840cd4b4b517e',
    'gd-ca.der': 'd06a3daedd39fc3050f30af50b4c923352cabb4f2ab81d833c999f63f5a7cbe0',
    'hello-pca.der': 'dbfc7be1149785b5fd98a995b83184f51de39e9b277be287082f57514007c9c1',
}


def put(root, absolute, data, mode=0o644):
    path = root / absolute.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def verify_fprintd_abi(library):
    daemon = Path('/usr/libexec/fprintd')
    if not daemon.is_file():
        raise RuntimeError('Install fprintd before packaging so its libfprint ABI can be checked')
    imported = subprocess.check_output(['nm', '-D', daemon], text=True)
    exported = subprocess.check_output(['nm', '-D', library], text=True)
    required = {line.split()[-1] for line in imported.splitlines() if ' U fp_' in line}
    available = {line.split()[-1].replace('@@', '@') for line in exported.splitlines() if ' T fp_' in line}
    if not required <= available:
        missing = ', '.join(sorted(required - available))
        raise RuntimeError(f'The built libfprint is missing fprintd ABI symbols: {missing}')


def main():
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='0.1.0')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    if subprocess.run(['dpkg', '--validate-version', args.version], capture_output=True).returncode:
        parser.error(f'Not a Debian-compatible version: {args.version}')
    if not LIBRARY.is_file() or not MANIFEST.is_file():
        parser.error('Build first with: python3 scripts/build_native.py')
    if not shutil.which('dpkg-deb'):
        parser.error('Install dpkg-dev to provide dpkg-deb')
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get('development') is not False:
        parser.error('A production build is required; development builds cannot be packaged')
    if hashlib.sha256(LIBRARY.read_bytes()).hexdigest() != manifest.get('library_sha256'):
        parser.error('Staged library does not match its build manifest')
    try:
        verify_fprintd_abi(LIBRARY)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    for source, expected in manifest['sources'].items():
        path = ROOT / source
        if path.parent != ROOT / 'native' or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            parser.error(f'Native source differs from the tested build: {source}')

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='petaic-deb-') as temporary:
        stage = Path(temporary) / 'package'
        libdir = stage / 'opt/weact-fingerprint/lib'
        libdir.mkdir(parents=True)
        shutil.copyfile(LIBRARY, libdir / LIBRARY.name)
        os.symlink(LIBRARY.name, libdir / 'libfprint-2.so.2')
        os.symlink('libfprint-2.so.2', libdir / 'libfprint-2.so')

        source_certs = ROOT / 'certs/sdcp'
        for name, expected in CERT_HASHES.items():
            data = (source_certs / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                parser.error(f'Bundled certificate does not match its pinned digest: {name}')
            put(stage, f'/etc/libfprint/petaicmoc/{name}', data)
            put(stage, f'/usr/libexec/petaic-moc/certs/sdcp/{name}', data)
        for name in ('pin_native_reader.py', 'petaic_transport.py', 'sdcp.py'):
            put(stage, f'/usr/libexec/petaic-moc/scripts/{name}', (ROOT / 'scripts' / name).read_bytes())
        put(stage, '/etc/systemd/system/fprintd.service.d/80-petaic-moc.conf',
            b'[Service]\nEnvironment="LD_LIBRARY_PATH=/opt/weact-fingerprint/lib"\n')
        put(stage, '/etc/udev/rules.d/70-petaic-moc.rules',
            b'ACTION=="add|change", SUBSYSTEM=="usb", ATTR{idVendor}=="28e9", ATTR{idProduct}=="5159", TAG+="uaccess"\n')
        put(stage, f'/usr/share/doc/{PACKAGE}/README.md', (ROOT / 'README.md').read_bytes())
        put(stage, f'/usr/share/doc/{PACKAGE}/copyright', (ROOT / 'LICENSE').read_bytes())

        control = stage / 'DEBIAN'
        control.mkdir()
        (control / 'control').write_text(
            f'Package: {PACKAGE}\n'
            f'Version: {args.version}\n'
            'Section: misc\nPriority: optional\nArchitecture: amd64\n'
            'Maintainer: PetaIC MOC Driver Maintainers <iewil@users.noreply.github.com>\n'
            'Depends: fprintd (>= 1.94.3), python3, python3-usb, python3-cryptography, '
            'libglib2.0-0t64, libgusb2, libjson-glib-1.0-0, libusb-1.0-0, libssl3t64, systemd, udev\n'
            'Recommends: libpam-fprintd\n'
            'Description: Experimental PetaIC MOC libfprint driver\n'
            ' Native libfprint backend for the WeAct/PetaIC USB fingerprint reader.\n'
            ' Tested with Package 2 of the linked product listing on Linux Mint 22.\n'
            ' A local reader trust pin is required after installation.\n'
        )
        (control / 'postinst').write_text('''#!/bin/sh
set -e
if [ "$1" = configure ]; then
    systemctl daemon-reload || true
    udevadm control --reload-rules || true
    udevadm trigger --subsystem-match=usb --attr-match=idVendor=28e9 --attr-match=idProduct=5159 || true
    systemctl try-restart fprintd.service || true
fi
exit 0
''')
        (control / 'prerm').write_text('''#!/bin/sh
set -e
case "$1" in
    remove)
        systemctl stop fprintd.service || true
        ;;
    upgrade|deconfigure)
        systemctl stop fprintd.service || true
        ;;
esac
exit 0
''')
        (control / 'postrm').write_text('''#!/bin/sh
set -e
case "$1" in
    remove|purge)
        systemctl daemon-reload || true
        udevadm control --reload-rules || true
        systemctl start fprintd.service || true
        ;;
esac
exit 0
''')
        for name in ('postinst', 'prerm', 'postrm'):
            (control / name).chmod(0o755)
        (control / 'conffiles').write_text(
            '/etc/libfprint/petaicmoc/root.der\n'
            '/etc/libfprint/petaicmoc/gd-ca.der\n'
            '/etc/libfprint/petaicmoc/hello-pca.der\n'
            '/etc/systemd/system/fprintd.service.d/80-petaic-moc.conf\n'
            '/etc/udev/rules.d/70-petaic-moc.rules\n'
        )

        for path in stage.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file():
                path.chmod(path.stat().st_mode & 0o755)

        output = args.output_dir.resolve() / f'{PACKAGE}_{args.version}_amd64.deb'
        subprocess.run(['dpkg-deb', '--build', '--root-owner-group', stage, output], check=True)
    print(f'Created {output}')


if __name__ == '__main__':
    main()
