#!/usr/bin/env python3
"""Install/remove the isolated fprintd backend. Preview by running without flags.

Installation requires sudo. Does not enable PAM or copy development fingerprint
records. System enrollment/verification is a separate step before PAM is enabled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = Path(os.environ.get(
    'WEACT_RESEARCH_ARCHIVE',
    ROOT.parent / 'WeAct_Hello_USB_Fingerprint_Reader_Research_Archive',
)).expanduser()
PREFIX = Path('/opt/weact-fingerprint')
CERTS = Path('/etc/libfprint/petaicmoc')
OVERRIDE = Path('/etc/systemd/system/fprintd.service.d/80-weact.conf')
RULE = Path('/etc/udev/rules.d/70-weact-fingerprint.rules')
STATE = Path('/var/lib/weact-fingerprint/install-state.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    subprocess.run([str(a) for a in args], check=True)


def write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f'Refusing symlink destination: {path}')
    fd, temporary = tempfile.mkstemp(prefix='.weact-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def inputs():
    manifest = json.loads((ROOT / 'build/native-production/petaic-build-manifest.json').read_text())
    if manifest['development'] is not False:
        raise ValueError('Development libraries cannot be installed system-wide')
    for name, sha in manifest['sources'].items():
        path = ROOT / name
        if path.parent != ROOT / 'native' or digest(path) != sha:
            raise ValueError('Native source changed since production build; rebuild first')
    library = ARCHIVE / 'private/native-stage/opt/weact-fingerprint/lib/libfprint-2.so.2.0.0'
    if digest(library) != manifest['library_sha256']:
        raise ValueError('Staged library differs from production build manifest')
    policy = ARCHIVE / 'private/native-policy.ini'
    if not policy.is_file() or policy.is_symlink() or policy.stat().st_mode & 0o022:
        raise ValueError('Prepare a protected reader pin before installation')
    # fprintd must resolve every imported libfprint symbol using this library.
    imported = subprocess.check_output(['nm', '-D', '/usr/libexec/fprintd'], text=True)
    exported = subprocess.check_output(['nm', '-D', str(library)], text=True)
    required = {line.split()[-1] for line in imported.splitlines() if ' U fp_' in line}
    available = {line.split()[-1].replace('@@', '@') for line in exported.splitlines() if ' T fp_' in line}
    if not required <= available:
        raise ValueError('Production library does not satisfy installed fprintd ABI')
    dynamic = subprocess.check_output(['readelf', '-d', str(library)], text=True)
    if '/home/' in dynamic or '/private/' in dynamic:
        raise ValueError('Production library contains development runtime paths')
    if b'/private/native-policy.ini' in library.read_bytes() or b'/private/sdcp-certificates' in library.read_bytes():
        raise ValueError('Production library embeds a development trust policy')
    files = {
        PREFIX / 'lib/libfprint-2.so.2.0.0': (library.read_bytes(), 0o644),
        CERTS / 'policy.ini': (policy.read_bytes(), 0o600),
        OVERRIDE: (b'[Service]\nEnvironment="LD_LIBRARY_PATH=/opt/weact-fingerprint/lib"\n', 0o644),
        RULE: (b'ACTION=="add|change", SUBSYSTEM=="usb", ATTR{idVendor}=="28e9", ATTR{idProduct}=="5159", TAG+="uaccess"\n', 0o644),
    }
    expected = {
        'root.der': '4c25971e3bdde59d178f7a5ef62561e9e88edd93c274ddaa522840cd4b4b517e',
        'gd-ca.der': 'd06a3daedd39fc3050f30af50b4c923352cabb4f2ab81d833c999f63f5a7cbe0',
        'hello-pca.der': 'dbfc7be1149785b5fd98a995b83184f51de39e9b277be287082f57514007c9c1',
    }
    for name, sha in expected.items():
        path = ROOT / 'certs/sdcp' / name
        if digest(path) != sha: raise ValueError(f'Wrong pinned public certificate: {name}')
        files[CERTS / name] = (path.read_bytes(), 0o644)
    return files, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    flags = parser.add_mutually_exclusive_group()
    flags.add_argument('--install', action='store_true')
    flags.add_argument('--update', action='store_true', help='Safely update an existing managed installation')
    flags.add_argument('--remove', action='store_true')
    flags.add_argument('--enable-unlock', action='store_true', help='Enable Cinnamon screen unlock with password fallback')
    flags.add_argument('--debug-driver', action='store_true', help='Log capture quality and match decisions, never identities or keys')
    args = parser.parse_args()
    if args.enable_unlock or args.debug_driver:
        if os.geteuid() != 0: raise PermissionError('Run this system configuration step with sudo')
        state = json.loads(STATE.read_text())
        if args.debug_driver:
            if digest(OVERRIDE) != state['files'][str(OVERRIDE)]:
                raise ValueError('fprintd override changed after installation')
            text = OVERRIDE.read_bytes()
            if b'G_MESSAGES_DEBUG=' not in text:
                text += b'Environment="G_MESSAGES_DEBUG=libfprint-petaicmoc"\n'
            write(OVERRIDE, text, 0o644)
            state['files'][str(OVERRIDE)] = digest(OVERRIDE)
            write(STATE, (json.dumps(state, indent=2) + '\n').encode(), 0o600)
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'restart', 'fprintd'])
            print('Enabled scoped driver diagnostics; no keys, secure IDs or raw payloads are logged.')
            return
        pam = Path('/etc/pam.d/cinnamon-screensaver')
        if 'screensaver_backup' in state:
            if digest(pam) != state['screensaver_sha256']:
                raise ValueError('Screensaver PAM changed after setup')
            print('Cinnamon fingerprint unlock is already enabled.')
            return
        original = pam.read_text()
        if pam.is_symlink() or original.splitlines() != ['@include common-auth', 'auth optional pam_gnome_keyring.so']:
            raise ValueError('Screensaver PAM differs from the inspected Mint configuration; refusing an automatic edit')
        new = 'auth sufficient pam_fprintd.so max-tries=1 timeout=10\n' + original
        state['screensaver_backup'] = original
        state['screensaver_sha256'] = hashlib.sha256(new.encode()).hexdigest()
        # Save the rollback record before changing the authentication file.
        write(STATE, (json.dumps(state, indent=2) + '\n').encode(), 0o600)
        write(pam, new.encode(), 0o644)
        print('Enabled fingerprint unlock for Cinnamon; the existing password path remains available.')
        return
    if args.update:
        if os.geteuid() != 0: raise PermissionError('Run update with sudo')
        state = json.loads(STATE.read_text())
        files, manifest = inputs()
        installed = {Path(name): sha for name, sha in state['files'].items()}
        if set(installed) != set(files): raise ValueError('Managed installation paths differ; refusing update')
        for path, expected in installed.items():
            if not path.is_file() or path.is_symlink() or digest(path) != expected:
                raise ValueError(f'Installed file changed; refusing update: {path}')
        library = PREFIX / 'lib/libfprint-2.so.2.0.0'
        if not (PREFIX / 'lib/libfprint-2.so').is_symlink() or (PREFIX / 'lib/libfprint-2.so').readlink().as_posix() != 'libfprint-2.so.2':
            raise ValueError('Managed libfprint soname link changed; refusing update')
        if not (PREFIX / 'lib/libfprint-2.so.2').is_symlink() or (PREFIX / 'lib/libfprint-2.so.2').readlink().as_posix() != 'libfprint-2.so.2.0.0':
            raise ValueError('Managed libfprint version link changed; refusing update')
        original = library.read_bytes()
        original_state = STATE.read_bytes()
        updated_state = dict(state)
        updated_state['files'] = dict(state['files'])
        updated_state['files'][str(library)] = hashlib.sha256(files[library][0]).hexdigest()
        try:
            run(['systemctl', 'stop', 'fprintd'])
            write(library, files[library][0], files[library][1])
            write(STATE, (json.dumps(updated_state, indent=2) + '\n').encode(), 0o600)
            run(['systemctl', 'start', 'fprintd'])
        except BaseException:
            write(library, original, 0o644)
            write(STATE, original_state, 0o600)
            subprocess.run(['systemctl', 'start', 'fprintd'], check=False)
            raise
        print('Managed backend updated; certificates, policy, diagnostics and PAM settings were retained.')
        return
    if args.remove:
        if os.geteuid() != 0: raise PermissionError('Run removal with sudo')
        state = json.loads(STATE.read_text())
        files = [Path(name) for name in state['files']]
        allowed = {PREFIX / 'lib/libfprint-2.so.2.0.0', CERTS / 'policy.ini', OVERRIDE, RULE,
                   CERTS / 'root.der', CERTS / 'gd-ca.der', CERTS / 'hello-pca.der'}
        if set(files) != allowed: raise ValueError('Invalid installed-state paths')
        for path in files:
            if not path.is_file() or path.is_symlink() or digest(path) != state['files'][str(path)]:
                raise ValueError(f'Installed file changed; refusing automatic removal: {path}')
        if 'screensaver_backup' in state:
            pam = Path('/etc/pam.d/cinnamon-screensaver')
            if digest(pam) != state['screensaver_sha256']:
                raise ValueError('Screensaver PAM changed after setup; refusing to overwrite it')
            write(pam, state['screensaver_backup'].encode(), 0o644)
        run(['systemctl', 'stop', 'fprintd'])
        for path in files: path.unlink()
        for name in ['libfprint-2.so.2', 'libfprint-2.so']:
            path = PREFIX / 'lib' / name
            if path.is_symlink(): path.unlink()
        STATE.unlink()
        run(['systemctl', 'daemon-reload'])
        run(['udevadm', 'control', '--reload-rules'])
        print('Removed WeAct backend override; Mint packaged libfprint and password authentication restored.')
        return
    files, manifest = inputs()
    print('Install production backend for USB 28e9:5159:')
    for path in files: print(f'  {path}')
    print('  Relative libfprint soname links under /opt/weact-fingerprint/lib')
    print('Mint packages remain installed. PAM and Linux enrollment are not changed by installation.')
    if not args.install:
        print('Reviewed installation command: sudo python3 scripts/install_native.py --install')
        return
    if os.geteuid() != 0: raise PermissionError('Run installation with sudo')
    if STATE.exists() or STATE.is_symlink() or any(path.exists() or path.is_symlink() for path in files):
        raise ValueError('Installation destination already exists; remove the previous managed installation first')
    for path in [*files, STATE]:
        for directory in path.parents:
            if directory.exists() and (directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o022):
                raise ValueError(f'Unsafe installation directory: {directory}')
    completed = []
    links = []
    try:
        run(['systemctl', 'stop', 'fprintd'])
        for path, (data, mode) in files.items():
            write(path, data, mode); completed.append(path)
        for name in ['libfprint-2.so.2', 'libfprint-2.so']:
            path = PREFIX / 'lib' / name
            path.symlink_to('libfprint-2.so.2.0.0'); links.append(path)
        write(STATE, (json.dumps({'files': {str(p): digest(p) for p in files},
                                  'upstream': manifest['upstream']}, indent=2) + '\n').encode(), 0o600)
        run(['systemctl', 'daemon-reload'])
        run(['udevadm', 'control', '--reload-rules'])
        run(['systemctl', 'start', 'fprintd'])
    except BaseException:
        for path in completed + links:
            if path.exists() or path.is_symlink(): path.unlink()
        if STATE.exists(): STATE.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=False)
        subprocess.run(['systemctl', 'start', 'fprintd'], check=False)
        raise
    print('Production fprintd backend installed. Next: enroll and verify using fprintd before enabling PAM.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Native installation failed: {error}', file=sys.stderr)
        sys.exit(1)
