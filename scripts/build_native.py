#!/usr/bin/env python3
"""Overlay and build the native backend in a pinned, isolated libfprint checkout.

No installation. --development embeds private paths and allows a user-owned pin;
the normal build requires a root-owned policy under /etc/libfprint/petaicmoc.
"""
import argparse
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/petaicmoc-work'
UPSTREAM = '6f9479c3d55f847c1b3769f28ceb99227f9858cf'


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--development', action='store_true')
    parser.add_argument('--clean', action='store_true', help='Reset only the generated native build directory')
    parser.add_argument('--fetch-deps', action='store_true', help='Download/extract Ubuntu development packages locally, without installation')
    args = parser.parse_args()
    if args.fetch_deps:
        packages = WORK / 'build-deps/packages'
        sysroot = WORK / 'build-deps/sysroot'
        packages.mkdir(parents=True, exist_ok=True)
        run(['apt-get', 'download', 'libgusb-dev', 'libgusb2', 'libusb-1.0-0-dev',
             'libusb-1.0-0', 'libjson-glib-dev', 'libjson-glib-1.0-0', 'meson'], cwd=packages)
        for package in packages.glob('*.deb'):
            run(['dpkg-deb', '-x', package, sysroot])
        for pc in sysroot.glob('usr/lib/*/pkgconfig/*.pc'):
            pc.write_text(pc.read_text().replace('prefix=/usr', f'prefix={sysroot}/usr'))
    source = WORK / 'libfprint-upstream'
    source.parent.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        run(['git', 'clone', '--filter=blob:none', 'https://gitlab.freedesktop.org/libfprint/libfprint.git', source])
        run(['git', '-C', source, 'checkout', '--detach', UPSTREAM])
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if head != UPSTREAM:
        raise ValueError(f'Expected upstream {UPSTREAM}, found {head}; refusing to overwrite another checkout')
    dest = source / 'libfprint/drivers/petaicmoc'
    dest.mkdir(exist_ok=True)
    for name in ['petaicmoc.c', 'petaic-proto.c', 'petaic-proto.h', 'petaic-sdcp.c', 'petaic-sdcp.h']:
        shutil.copyfile(ROOT / 'native' / name, dest / name)
    top = source / 'meson.build'
    text = top.read_text()
    if "'petaicmoc':" not in text:
        text = text.replace("drivers_info = {", "drivers_info = {\n    'petaicmoc': { 'helper': ['openssl'] },", 1)
    top.write_text(text)
    options = source / 'meson_options.txt'
    text = options.read_text()
    if "option('petaic-development'" not in text:
        text += "\noption('petaic-development', type: 'boolean', value: false)\n"
    # The work directory is generated state; keep it named independently of
    # the removed research archive and ensure it exists on fresh upstream trees.
    if "option('petaic-work-dir'" not in text:
        text += "option('petaic-work-dir', type: 'string', value: '')\n"
    options.write_text(text)
    library = source / 'libfprint/meson.build'
    text = library.read_text()
    if "'petaicmoc' :" not in text:
        text = text.replace('driver_sources = {', "driver_sources = {\n    'petaicmoc' : files('drivers/petaicmoc/petaicmoc.c', 'drivers/petaicmoc/petaic-proto.c', 'drivers/petaicmoc/petaic-sdcp.c'),", 1)
    library.write_text(text)
    overlay = source / 'petaic-native'
    overlay.mkdir(exist_ok=True)
    for name in ['harness.c', 'test-native.c', 'petaic-proto.c', 'petaic-proto.h', 'petaic-sdcp.c', 'petaic-sdcp.h']:
        shutil.copyfile(ROOT / 'native' / name, overlay / name)
    (overlay / 'meson.build').write_text('''
executable('petaic-harness', 'harness.c', dependencies: libfprint_dep)
native_test = executable('petaic-native-tests', ['test-native.c', 'petaic-proto.c', 'petaic-sdcp.c'], dependencies: [gio_dep, dependency('openssl')])
test('petaic-native', native_test)
''')
    text = top.read_text()
    if "subdir('petaic-native')" not in text:
        text += "\nsubdir('petaic-native')\n"
    if '# PetaIC per-build trust configuration' not in text:
        text += f'''
# PetaIC per-build trust configuration
petaic_conf = configuration_data()
if get_option('petaic-development')
  petaic_conf.set('PETAIC_DEVELOPMENT_BUILD', 1)
  petaic_base = get_option('petaic-work-dir')
  petaic_conf.set_quoted('PETAIC_CERT_DIR', '{ROOT / "certs/sdcp"}')
  petaic_conf.set_quoted('PETAIC_POLICY_PATH', petaic_base / 'private/native-policy.ini')
else
  petaic_conf.set('PETAIC_DEVELOPMENT_BUILD', 0)
  petaic_conf.set_quoted('PETAIC_CERT_DIR', '/etc/libfprint/petaicmoc')
  petaic_conf.set_quoted('PETAIC_POLICY_PATH', '/etc/libfprint/petaicmoc/policy.ini')
endif
configure_file(output: 'petaic-build-config.h', configuration: petaic_conf)
'''
    top.write_text(text)
    build = ROOT / ('build/native-development' if args.development else 'build/native-production')
    # Remove the legacy source-scoped config; each Meson build owns its header.
    legacy = dest / 'petaic-build-config.h'
    if legacy.exists(): legacy.unlink()
    env = os.environ.copy()
    sysroot = WORK / 'build-deps/sysroot'
    if sysroot.exists():
        for pc in sysroot.glob('usr/lib/*/pkgconfig/*.pc'):
            contents = pc.read_text()
            contents = re.sub(r'^prefix=.*?/sysroot/usr$', f'prefix={sysroot}/usr', contents, flags=re.M)
            pc.write_text(contents)
    if sysroot.exists():
        env['PKG_CONFIG_PATH'] = str(sysroot / 'usr/lib/x86_64-linux-gnu/pkgconfig')
        env['LD_LIBRARY_PATH'] = str(sysroot / 'usr/lib/x86_64-linux-gnu')
        env['PYTHONPATH'] = str(sysroot / 'usr/lib/python3/dist-packages')
    meson = shutil.which('meson') or str(sysroot / 'usr/bin/meson')
    prefix = WORK / 'native-prefix' if args.development else Path('/opt/weact-fingerprint')
    command = [meson, 'setup', build, source, '--prefix', prefix, '--libdir', 'lib',
               '-Ddrivers=petaicmoc', '-Dintrospection=false', '-Ddoc=false',
               '-Dinstalled-tests=false', '-Dudev_rules=disabled', '-Dudev_hwdb=disabled',
               f'-Dpetaic-development={str(args.development).lower()}',
               f'-Dpetaic-work-dir={WORK}',
               '-Dc_args=[]']
    if (build / 'build.ninja').exists():
        if args.clean:
            shutil.rmtree(build)
        else:
            command.append('--reconfigure')
    run(command, env=env)
    run([meson, 'compile', '-C', build], env=env)
    run([meson, 'test', '-C', build, 'petaic-native', '--print-errorlogs'], env=env)
    if not args.development:
        stage = ROOT / 'build/native-stage'
        run([meson, 'install', '-C', build, '--destdir', stage], env=env)
        library = stage / 'opt/weact-fingerprint/lib/libfprint-2.so.2.0.0'
        manifest = {
            'upstream': UPSTREAM, 'development': False,
            'library_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
            'sources': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in sorted((ROOT / 'native').glob('*')) if path.is_file()},
        }
        (build / 'petaic-build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(f'Production library staged under {stage}; system installation not performed.')


if __name__ == '__main__':
    main()
