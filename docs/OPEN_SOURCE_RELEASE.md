# Open-source release checklist

The current source tree and reachable `main` history have been prepared for publication. This repository remains private; this work does not change GitHub visibility.

## Completed in the current tree

- Added the LGPL-2.1-or-later license and third-party notices.
- Added build/install, security, architecture, and contribution documentation.
- Removed the generated source ZIP, its generator, and machine-specific host-observation appendix.
- Kept vendor binaries, raw USB captures, per-reader trust pins, and enrollment records out of the source tree.
- Replaced user- and machine-specific references in the current documentation.
- Rewrote reachable `main` history to remove older copies of the host observations and generated bundles, scrub the local account name, and normalize a placeholder commit email.
- Renamed the GitHub repository to `libfprint-petaic-moc` and clarified that hardware testing used Package 2 of the linked product listing.
- Added a Code of Conduct, citation metadata, privacy-conscious issue forms, Dependabot configuration, build/native-test CI, and a CodeQL workflow for when the repository is public.
- Enabled Dependabot alerts and security updates on GitHub.

## Required before making the repository public

Before changing repository visibility, repeat a full-history scan for private capture material, vendor binaries, credentials, fingerprints, device serials, local paths, and obsolete links. Enable GitHub's secret scanning and push protection and private vulnerability reporting after publication; these features are not available for this user-owned private repository on the current plan. Then publish the repository and confirm its README, license, build guide, issue-reporting path, and automated CodeQL results are visible.
