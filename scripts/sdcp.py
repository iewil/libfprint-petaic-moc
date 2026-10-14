"""SDCP v1 cryptographic primitives, implemented from Microsoft's public spec.

This verifies certificate signatures/validity, attestation and the session MAC.
It does not implement current certificate revocation or firmware revocation policy,
and must not be used as a production authentication backend yet.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


MICROSOFT_ROOT_SHA256 = "4c25971e3bdde59d178f7a5ef62561e9e88edd93c274ddaa522840cd4b4b517e"


def _certificate_time(cert, name):
    """Return certificate validity fields as timezone-aware UTC datetimes."""
    value = getattr(cert, f"{name}_utc", None)
    if value is not None:
        return value
    return getattr(cert, name).replace(tzinfo=timezone.utc)


def kdf(key, label, context=b"", size=32):
    if len(key) != 32 or not 1 <= size <= 4096:
        raise ValueError("Invalid KDF key/output size")
    encoded_label = label.encode("ascii")
    if b"\0" in encoded_label:
        raise ValueError("KDF label must not contain a null byte")
    fixed = encoded_label + b"\0" + context + struct.pack(">I", size * 8)
    return b"".join(hmac.digest(key, struct.pack(">I", i) + fixed, "sha256")
                    for i in range(1, (size + 31) // 32 + 1))[:size]


def labelled_mac(key, label, data):
    if len(key) != 32 or "\0" in label:
        raise ValueError("Invalid MAC key/label")
    return hmac.digest(key, label.encode("ascii") + b"\0" + data, "sha256")


def public_key(encoded):
    if len(encoded) != 65 or encoded[0] != 4:
        raise ValueError("Expected uncompressed P256 public key")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)


def verify_signature(key, data, signature):
    if len(signature) != 64 or not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Invalid SDCP signature/key")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    key.verify(utils.encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))


def audit_certificates(model_der, ca_ders, root_der, *, now=None):
    # Fixed Microsoft root, fetched independently of the reader/vendor DLL.
    if hashlib.sha256(root_der).hexdigest() != MICROSOFT_ROOT_SHA256:
        raise ValueError("Unrecognized Microsoft Devices trust root")
    now = now or datetime.now(timezone.utc)
    chain = [x509.load_der_x509_certificate(model_der)]
    chain.extend(x509.load_der_x509_certificate(data) for data in ca_ders)
    root = x509.load_der_x509_certificate(root_der)
    chain.append(root)
    validity_errors = []
    for n, cert in enumerate(chain):
        # cryptography added timezone-aware certificate properties in v42.
        # Keep the research tools compatible with distro versions that expose
        # only the older naive-UTC properties.
        valid_from = _certificate_time(cert, "not_valid_before")
        valid_until = _certificate_time(cert, "not_valid_after")
        if not valid_from <= now <= valid_until:
            validity_errors.append({
                "chain_index": n,
                "subject": cert.subject.rfc4514_string(),
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_until.isoformat(),
                "reason": "expired" if now > valid_until else "not yet valid",
            })
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if n == 0:
            if constraints.ca:
                raise ValueError("Model certificate must not be a CA")
        else:
            if not constraints.ca:
                raise ValueError("Issuer certificate is not a CA")
            if constraints.path_length is not None and n - 1 > constraints.path_length:
                raise ValueError("Certificate path-length constraint exceeded")
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.key_cert_sign:
                raise ValueError("Issuer does not permit certificate signing")
        issuer = chain[n + 1] if n + 1 < len(chain) else cert
        if cert.issuer != issuer.subject:
            raise ValueError("Certificate issuer does not match chain")
        key = issuer.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("Unexpected non-ECC certificate issuer")
        key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        # Do not silently accept policy constraints this limited verifier cannot enforce.
        supported = {x509.ExtensionOID.BASIC_CONSTRAINTS, x509.ExtensionOID.KEY_USAGE}
        for extension in cert.extensions:
            if extension.critical and extension.oid not in supported:
                raise ValueError(f"Unsupported critical certificate extension: {extension.oid}")
    model = chain[0]
    key = model.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Model certificate does not have a P256 key")
    try:
        usage = model.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("Model key does not permit signatures")
    except x509.ExtensionNotFound:
        pass
    return model, validity_errors


def validate_certificates(model_der, ca_ders, root_der, *, now=None):
    model, validity_errors = audit_certificates(model_der, ca_ders, root_der, now=now)
    if validity_errors:
        error = validity_errors[0]
        raise ValueError(f"Certificate is {error['reason']}: {error['subject']} "
                         f"(valid until {error['valid_until']})")
    return model


@dataclass(frozen=True)
class Claim:
    device_random: bytes
    mac: bytes
    model_certificate: bytes
    device_public_key: bytes
    firmware_public_key: bytes
    firmware_hash: bytes
    model_signature: bytes
    firmware_signature: bytes

    @classmethod
    def parse(cls, payload):
        # Fixed structure consumed by DLL RVA 0x2024 for this driver version.
        if len(payload) < 1155 or len(payload) > 2038:
            raise ValueError("Unexpected SDCP connect payload size")
        if any(payload[1155:]):
            raise ValueError("Unexpected nonzero data after SDCP claim")
        sizes = [32, 32, 801, 65, 65, 32, 64, 64]
        fields = []
        offset = 0
        for size in sizes:
            fields.append(bytes(payload[offset:offset + size]))
            offset += size
        return cls(*fields)

    def hash(self):
        return hashlib.sha256(self.model_certificate + self.device_public_key +
                              self.firmware_public_key + self.firmware_hash +
                              self.model_signature + self.firmware_signature).digest()

    def validate(self, host_key, host_random, ca_ders, root_der):
        model = validate_certificates(self.model_certificate, ca_ders, root_der)
        keys = self._verify_crypto(host_key, host_random, model)
        return keys, model

    def audit(self, host_key, host_random, ca_ders, root_der):
        """Report crypto/date checks separately; never return session keys."""
        model, validity_errors = audit_certificates(self.model_certificate, ca_ders, root_der)
        keys = self._verify_crypto(host_key, host_random, model)
        del keys
        return {
            "certificate_signature_chain": "valid",
            "device_and_firmware_signatures": "valid",
            "fresh_claim_mac": "valid",
            "certificate_time_policy": "rejected" if validity_errors else "valid",
            "certificate_time_errors": validity_errors,
            "model_certificate_subject": model.subject.rfc4514_string(),
            "model_certificate_expires": _certificate_time(model, "not_valid_after").isoformat(),
        }

    def _verify_crypto(self, host_key, host_random, model):
        if len(host_random) != 32 or not isinstance(host_key.curve, ec.SECP256R1):
            raise ValueError("Invalid host session inputs")
        verify_signature(model.public_key(), self.device_public_key, self.model_signature)
        device_key = public_key(self.device_public_key)
        verify_signature(device_key, b"\xc0\x01" + self.firmware_hash + self.firmware_public_key,
                         self.firmware_signature)
        shared = host_key.exchange(ec.ECDH(), public_key(self.firmware_public_key))
        master = kdf(shared, "master secret", host_random + self.device_random)
        keys = kdf(master, "application keys", size=64)
        expected = labelled_mac(keys[:32], "connect", self.hash())
        if not hmac.compare_digest(self.mac, expected):
            raise ValueError("SDCP claim MAC mismatch")
        return keys
