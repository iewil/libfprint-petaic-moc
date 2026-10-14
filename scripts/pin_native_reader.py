#!/usr/bin/env python3
"""Create a local, explicit expired-model exception pinned to reader and firmware.

Verifies all chain/attestation signatures and a fresh claim MAC before pinning.
This creates a development policy only; no system authentication is configured.
"""
import argparse
import hashlib
import os
from pathlib import Path
import sys
ARCHIVE = Path(os.environ.get(
    'WEACT_RESEARCH_ARCHIVE',
    Path(__file__).resolve().parents[2] / 'WeAct_Hello_USB_Fingerprint_Reader_Research_Archive',
)).expanduser()
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from petaic_transport import ResearchReader
from sdcp import Claim, _certificate_time, audit_certificates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', action='store_true')
    parser.add_argument('--output', type=Path, default=ARCHIVE / 'private/native-policy.ini')
    args = parser.parse_args()
    if not args.pin:
        parser.print_help()
        return
    directory = Path('certs/sdcp')
    root = (directory / 'root.der').read_bytes()
    cas = [(directory / name).read_bytes() for name in ['gd-ca.der', 'hello-pca.der']]
    key = ec.generate_private_key(ec.SECP256R1())
    random = os.urandom(32)
    public = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    with ResearchReader() as reader:
        claim = Claim.parse(reader.connect_payload(random, public))
    model, errors = audit_certificates(claim.model_certificate, cas, root)
    keys = claim._verify_crypto(key, random, model)
    del keys, key, random
    if any(e['chain_index'] != 0 or e['reason'] != 'expired' for e in errors):
        raise ValueError('Only an expired model certificate is eligible for this exception')
    values = {
        'device-key-sha256': hashlib.sha256(claim.device_public_key).hexdigest(),
        'firmware-sha256': claim.firmware_hash.hex(),
        'model-certificate-sha256': hashlib.sha256(claim.model_certificate).hexdigest(),
        'allow-expired-model': 'true',
    }
    contents = '# Explicit local exception; signatures/MAC and issuer dates remain mandatory.\n[reader]\n'
    contents += ''.join(f'{name}={value}\n' for name, value in values.items())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents silently replacing a previously trusted pin.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(contents)
    print(f'Pinned the cryptographically verified reader and current firmware in {args.output}')
    print(f'Model certificate expires: {_certificate_time(model, "not_valid_after").isoformat()}')
    print('Development policy only; fprintd/PAM unchanged.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Pin preparation failed: {error}', file=sys.stderr)
        sys.exit(1)
