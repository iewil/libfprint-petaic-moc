#!/usr/bin/env python3
"""Grant this Linux user access to the current reader node until reconnection.

Run in a terminal: python3 scripts/grant_usb_access.py
Uses sudo/setfacl for one exact 28e9:5159 device; creates no permanent udev rule.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    if not sys.platform.startswith("linux"):
        raise SystemExit("This access helper is only for Linux")
    nodes = []
    for device in Path("/sys/bus/usb/devices").iterdir():
        try:
            if ((device / "idVendor").read_text().strip() == "28e9" and
                    (device / "idProduct").read_text().strip() == "5159"):
                bus = int((device / "busnum").read_text())
                address = int((device / "devnum").read_text())
                nodes.append(Path(f"/dev/bus/usb/{bus:03d}/{address:03d}"))
        except FileNotFoundError:
            continue
    if len(nodes) != 1 or not nodes[0].exists():
        raise SystemExit(f"Expected one attached reader; found {len(nodes)}")
    if not shutil.which("setfacl"):
        raise SystemExit("setfacl is missing; install the acl package first")
    if os.getuid() == 0:
        raise SystemExit("Run as your regular user; the helper invokes sudo for setfacl")
    print(f"Granting user {os.getuid()} access to {nodes[0]} until it is reconnected", flush=True)
    subprocess.run(["sudo", "setfacl", "-m", f"u:{os.getuid()}:rw", str(nodes[0])], check=True)


if __name__ == "__main__":
    main()
