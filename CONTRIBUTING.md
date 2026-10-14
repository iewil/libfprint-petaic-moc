# Contributing

Contributions are welcome for protocol correctness, parser safety, distribution compatibility, reproducible builds, and documentation. Read [the security model](SECURITY.md) and the [package build and source installation instructions](README.md#build-the-debian-package) before changing trust or installation behavior.

## Before submitting a change

- Keep the native backend compatible with the pinned libfprint internal API, or update the pin and document the migration.
- Keep USB commands on the documented allowlist. Never add firmware update, database erase, template update, or deletion traffic without a separately reviewed design and explicit ownership model.
- Validate every SDCP signature, fresh MAC, identity, length, checksum, and timeout. Authentication must fail closed.
- Do not log secure identities, keys, match payloads, fingerprint samples, or raw captures.
- Keep user/system changes reversible. Avoid editing distribution files under `/usr`; extend the managed installer and rollback state instead.
- Add native parser and policy tests for new protocol behavior. Use synthetic inputs; never commit a user's USB trace or print record.
- Run `python3 scripts/build_native.py` for the native overlay. The script builds and runs the native checks.

## Public data policy

Never commit raw USB captures, vendor binaries, device-specific trust pins, fprintd print records, credentials, or other private device data. Keep protocol findings reproducible through descriptions and synthetic tests rather than raw biometric traffic. Review changes and history for private data before publication.

## Upstreaming

The long-term goal is a reviewable upstream libfprint driver. Keep vendor binaries out of the source and build, document provenance for protocol findings, and follow the upstream project's current contribution and testing guidance before proposing integration.
