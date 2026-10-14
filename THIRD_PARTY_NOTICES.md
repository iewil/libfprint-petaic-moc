# Third-party notices

This repository does not include the WeAct Windows driver, USB capture files, or libfprint source checkout. The required public SDCP attestation certificates are included and verified by hash.

- **libfprint**: the build helper fetches upstream libfprint at the commit recorded in `scripts/build_native.py`, overlays this project's driver, and builds it. Upstream source and any resulting combined library remain under libfprint's own license. See [the libfprint project](https://gitlab.freedesktop.org/libfprint/libfprint).
- **Python runtime dependencies** are listed in `requirements.txt` and installed from their package repositories; they are not vendored here and retain their own licenses.
- **Microsoft SDCP and certificates**: the protocol is implemented from the published [Secure Device Connection Protocol specification](https://github.com/microsoft/SecureDeviceConnectionProtocol/wiki/Secure-Device-Connection-Protocol). The public attestation certificates required at runtime are included under `certs/sdcp/`; their provenance and SHA-256 hashes are documented there. The GigaDevice intermediate was extracted from the inspected WeAct package. The vendor package is not required to build or install the driver.
- **WeAct driver package**: used only as an optional local reverse-engineering input. The Windows binaries and package are not copied, linked, executed, or redistributed by this project.

The license for original files in this repository is in [LICENSE](LICENSE).
