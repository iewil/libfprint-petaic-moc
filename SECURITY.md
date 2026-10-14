# Security model and limitations

## What the driver trusts

The driver does not trust a match flag by itself. It opens a fresh Secure Device Connection Protocol (SDCP) session, validates the certificate chain and reader/firmware attestations, checks a fresh claim MAC, snapshots the identities in the existing reader database, and validates the MAC on each identification result. A successful result must refer to an identity in that snapshot. libfprint then compares that identity with the current Linux account's saved print.

The model certificate in the tested reader expired on 2025-05-15. Strict certificate-time checks would reject this reader. This project's explicit exception accepts only an expired model certificate whose certificate, public key, and firmware hash match a protected local pin. It continues to validate issuer dates, chain signatures, attestation signatures, and fresh MACs. It does not make other expired or not-yet-valid certificates acceptable.

The pin is a trust-on-first-use decision made after a live cryptographic check. It does not establish vendor approval, repair certificate revocation, or prove firmware is free of vulnerabilities. Re-pin only after independently authenticating a replacement device and firmware. Do not copy a pin from another computer as a substitute for that check.

## Data and system changes

- The sensor and its existing secure database retain fingerprint templates. The Linux print stores an authorization identity and reader/firmware binding, not a fingerprint image or template.
- Enrollment uses only the reader transaction implemented and tested by this backend. The driver does not provide arbitrary template update or deletion commands.
- The installer places the alternate libfprint build under `/opt/weact-fingerprint`, with its own fprintd service environment, root-owned trust policy, and device-scoped udev rule. It does not replace the distribution package files.
- Cinnamon unlock is an explicit separate option. It changes only `/etc/pam.d/cinnamon-screensaver`, retaining the existing `common-auth` password path. Login, sudo, LightDM, and global PAM configuration are not changed.
- The installer records hashes and the original Cinnamon PAM text, and refuses automatic removal if managed files have changed.

## Known gaps

The project has not implemented certificate revocation or Microsoft firmware revocation. Linux-driven reader-side enrollment has completed successfully through fprintd on one reader and firmware; cancellation and broad hardware/firmware compatibility still require validation. The project has not measured false-accept rates or tested suspend/resume and all unplug cases. Treat this as experimental software, not a certified or sole authentication factor.

The Windows vendor DLL was reverse-engineered as data. It is not included, executed, loaded by the Linux backend, or required at runtime. Raw Windows USB captures and device-specific identity material are kept outside this repository in the local research archive and must not be published.

## Reporting a security issue

When the repository is public, report vulnerabilities through GitHub's private vulnerability reporting (the maintainers should enable it before publication). While it remains private, contact the repository owner through the contact options on the `@iewil` GitHub profile. Do not put exploit details, biometric records, or raw device captures in a public issue.
