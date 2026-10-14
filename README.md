# WeAct PetaIC fingerprint reader for Linux

This project adds an experimental native [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) backend for the WeAct/PetaIC USB fingerprint reader with USB ID `28e9:5159`. It has been verified on Linux Mint with fprintd, Cinnamon PAM, and a real Cinnamon screen unlock.

The reader performs matching on-device. The current backend stores an authorization record that associates a cryptographically authenticated reader identity with a Linux account and finger name. It does not copy biometric templates to the computer.

## Current status

- fprintd enrolled an existing reader-side finger and verified it successfully.
- An unenrolled finger was rejected by both the native backend and fprintd.
- A non-touching PAM attempt timed out to the normal password prompt.
- A real Cinnamon screen lock was unlocked with the enrolled finger.
- Linux-driven enrollment of a fresh finger completed all 12 accepted samples, committed the reader-side template, and confirmed it by storage readback. The resulting libfprint print survived save/reload and matched on a subsequent live verification.
- The fprintd path saves fresh Linux prints. Verification may need several scan attempts: the reader can reject initial captures and authenticate a later one. Fresh enrollment and eventual matching have been confirmed on this reader; broader device/firmware testing remains open.
- Enrollment retries an image-quality rejection without advancing the accepted sample count. Live negative-match, cancellation, and reconnect checks remain part of validation.
- The detailed protocol research and capture records are kept in a separate local research archive, outside this repository.

This remains experimental software. The reader's model certificate expired on 2025-05-15. The installation therefore requires a local policy pin for the reader's model certificate, device public key, and firmware hash. The exception allows only that pinned expired model certificate; issuer validity, signatures, firmware attestation, and fresh session MACs remain checked. Certificate revocation policy, suspend/resume, unplug recovery, long-term reliability, and biometric false-accept rates have not been established. Read [the security and trust model](docs/SECURITY.md) before installing it.

## Contents

- [Build, pin, install, and remove](docs/BUILDING.md)
- [Security model and limitations](docs/SECURITY.md)
- [Development and contribution guide](CONTRIBUTING.md)
- [Open-source release notes](docs/OPEN_SOURCE_RELEASE.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Quick start

Clone the repository, then follow [docs/BUILDING.md](docs/BUILDING.md). The build guide explains prerequisites, validating the bundled public SDCP certificates, creating the machine-specific reader pin, building against a pinned libfprint revision, and installing with rollback support.

The native installation does not enroll an account or alter PAM. After installing it, `fprintd-enroll` can create a new reader-side template directly from Linux; complete the positive and negative checks in [the build guide](docs/BUILDING.md) before enabling the narrowly scoped Cinnamon PAM entry. Password authentication remains available. Enrollment is experimentally verified on one reader and firmware; compatibility across other units and firmware versions is not established.

To remove the managed installation and restore the saved Cinnamon PAM configuration when unchanged:

```sh
sudo python3 scripts/install_native.py --remove
```

## License

The original project code is provided under the GNU Lesser General Public License, version 2.1 or (at your option) any later version. See [LICENSE](LICENSE). Upstream libfprint and other dependencies retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
