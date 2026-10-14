# Build and install

These instructions target a 64-bit Linux Mint 22.x/Ubuntu 24.04 system with the `28e9:5159` reader. The native build overlays a pinned upstream libfprint checkout; it does not modify the distribution's libfprint files. The installer uses an isolated prefix and has a managed rollback path.

## 1. Install build tools

```sh
sudo apt update
sudo apt install build-essential git ninja-build pkg-config python3-venv python3-pip libglib2.0-dev libssl-dev libusb-1.0-0 acl
```

Create the Python environment used by the USB reader pinning command:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

The native build helper downloads and extracts the Ubuntu `libgusb`, `libusb`, `libjson-glib`, and Meson development packages into the sibling research archive. It does not install those packages system-wide:

```sh
python3 scripts/build_native.py --fetch-deps
```

The research archive is stored beside this checkout at `../WeAct_Hello_USB_Fingerprint_Reader_Research_Archive`; set `WEACT_RESEARCH_ARCHIVE` to override that location. The build pins upstream libfprint to commit `6f9479c3d55f847c1b3769f28ceb99227f9858cf`, copies this project's backend into that checkout, configures only the PetaIC driver and compiles its focused protocol/policy checks. Each build runs the native checks automatically. `--clean` wipes only the generated native build directory before rebuilding.

## 2. Validate the public trust certificates

The verified public SDCP certificate chain is included under `certs/sdcp/`,
with provenance and expected SHA-256 digests in its README. The installer checks
these hashes before copying them into the root-owned runtime trust directory.
No vendor Windows driver package is needed to build or install the Linux
backend. The reader-specific key and firmware pin remains local to each machine.

## 3. Create a reader-specific trust pin

Connect the reader. Grant the current account access to this USB node until it is reconnected:

```sh
python3 scripts/grant_usb_access.py
```

Then verify the live attestation and write an exclusive, mode-0600 local policy:

```sh
.venv/bin/python scripts/pin_native_reader.py --pin
```

The command accepts only the expired model-certificate condition observed on this hardware. It refuses other chain validity errors and creates a pin for this reader's model certificate, device key, and current firmware. The pin is stored under `private/native-policy.ini` in the sibling `WeAct_Hello_USB_Fingerprint_Reader_Research_Archive` folder. Set `WEACT_RESEARCH_ARCHIVE` if you keep that folder elsewhere. This per-machine policy must remain private.

## 4. Build and review the production overlay

```sh
python3 scripts/build_native.py
python3 scripts/install_native.py
```

The last command is a preview. It checks the build manifest and hashes, ABI compatibility with the installed fprintd, library runtime paths, certificate pins, and local policy. Review that output before installing.

## 5. Install, enroll, and verify

Install the staged library, root-owned pin and certificates, fprintd systemd override, and udev rule:

```sh
sudo python3 scripts/install_native.py --install
```

For a later driver rebuild on a machine that already has the managed backend,
use `sudo python3 scripts/install_native.py --update`. It verifies the installed
files and symlinks before replacing only the backend library; local policy,
certificates, diagnostics, and PAM settings are retained.

This does not enable PAM or register a Linux account. As the regular desktop user, enroll a new finger directly on the reader:

```sh
fprintd-enroll -f right-index-finger "$USER"
fprintd-verify -f right-index-finger "$USER"
```

Enrollment creates a reader-side template and then saves account-bound authorization metadata through fprintd. Confirm that the enrolled finger matches and a finger that was not enrolled is rejected. Keep a password fallback available. This implementation is experimental and has been tested on one reader and firmware; cancellation and broader reader/firmware compatibility remain to be validated.

To enable only Cinnamon lock-screen authentication with password fallback:

```sh
sudo python3 scripts/install_native.py --enable-unlock
```

Use the PAM checks (they never collect or store a password), then test a real Cinnamon lock screen:

```sh
python3 scripts/check_screensaver_pam.py
python3 scripts/check_screensaver_pam.py --expect-fallback
cinnamon-screensaver-command --lock
```

The first PAM check waits for the enrolled finger. The fallback check waits without a touch and stops at the password prompt. After the desktop locks, unlock with the enrolled finger and verify that a normal password still works when the reader is unavailable or does not recognize a finger.

## Remove

The managed rollback restores Mint's packaged libfprint selection and the original Cinnamon PAM file if that file is unchanged:

```sh
sudo python3 scripts/install_native.py --remove
```

The registered Linux fprintd print remains in the user's fprintd storage. Remove only this finger's Linux authorization record with `fprintd-delete -f right-index-finger "$USER"` while the reader backend is available. Hardware database records are not deleted by project cleanup.
