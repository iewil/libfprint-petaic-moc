"""Bounded USB transport for info, SDCP connection and existing-database research."""

import math
import struct
import sys
import time


RESEARCH_COMMANDS = {0x0c, 0x10, 0x11, 0x30, 0x77, 0xc0, 0xc7, 0xd5, 0xd9, 0xdb}


def small_request(command, payload=b""):
    if command not in RESEARCH_COMMANDS:
        raise ValueError("Command is outside the research allowlist")
    if len(payload) > 120:
        raise ValueError("Small request exceeds frame capacity")
    packet = bytearray(128)
    struct.pack_into("<H", packet, 0, len(payload))
    packet[2] = command
    packet[6:6 + len(payload)] = payload
    struct.pack_into("<H", packet, 126, sum(packet[:126]) & 0xffff)
    return bytes(packet)


def small_response(packet, command, allowed_events=(1,)):
    if len(packet) != 128:
        raise ValueError("Small response must be 128 bytes")
    if struct.unpack_from("<H", packet, 126)[0] != sum(packet[:126]) & 0xffff:
        raise ValueError("Small response checksum mismatch")
    length = struct.unpack_from("<H", packet)[0]
    if length > 120:
        raise ValueError("Small response exceeds frame capacity")
    if packet[2:4] != bytes([command, 5]):
        raise ValueError("Small response command/marker mismatch")
    # DLL DumpInPacket RVA 0x5794 names byte 5 pre_ret_code (previous event).
    # An earlier command's error must not replace the current event at byte 4.
    if packet[4] not in allowed_events:
        raise ValueError(f"Small response has unexpected events {packet[4]:02x}/{packet[5]:02x}")
    return bytes(packet[6:6 + length])


def extended_request(command, payload):
    if command not in (0x77, 0xc7) or len(payload) != 2039:
        raise ValueError("Only documented 2048-byte SDCP connection/match requests are supported")
    packet = bytearray(2048)
    struct.pack_into("<I", packet, 4, len(payload))
    packet[8] = command
    packet[9:] = payload
    struct.pack_into("<I", packet, 0, sum(packet[4:]) & 0xffffffff)
    return bytes(packet)


def extended_response(packet, command, capacity=2038):
    if len(packet) != 2048 or capacity != 2038:
        raise ValueError("Unexpected extended response size/capacity")
    if struct.unpack_from("<I", packet)[0] != sum(packet[4:]) & 0xffffffff:
        raise ValueError("Extended response checksum mismatch")
    length = struct.unpack_from("<I", packet, 4)[0]
    if length > capacity or length > len(packet) - 10:
        raise ValueError("Extended response length exceeds capacity")
    if packet[8] != command or packet[9] != 1:
        raise ValueError(f"Extended response command/event mismatch ({packet[8]:02x}/{packet[9]:02x})")
    return bytes(packet[10:10 + length])


class ResearchReader:
    """Claim only the captured vendor-specific Linux reader, never reset it."""

    def __init__(self, timeout_ms=1500, progress=None):
        if not 100 <= timeout_ms <= 10000:
            raise ValueError("Timeout must be between 100 and 10000 ms")
        self.timeout_ms = timeout_ms
        self.device = None
        self.claimed = False
        self.detached = False
        self.setup_done = False
        self.progress = progress or (lambda message: None)

    def __enter__(self):
        if not sys.platform.startswith("linux"):
            raise ValueError("Live research is restricted to Linux")
        import usb.core
        import usb.util
        self.util = usb.util
        devices = list(usb.core.find(find_all=True, idVendor=0x28e9, idProduct=0x5159))
        if len(devices) != 1:
            raise ValueError(f"Expected one reader; found {len(devices)}")
        self.device = device = devices[0]
        try:
            configs = list(device)
            if (device.bcdDevice != 0x0100 or device.bDeviceClass != 0xff or
                    len(configs) != 1 or configs[0].bConfigurationValue != 1 or
                    configs[0].bNumInterfaces != 1):
                raise ValueError("Reader personality differs from captured vendor-specific layout")
            interfaces = list(configs[0])
            if len(interfaces) != 1:
                raise ValueError("Unexpected alternate interface settings")
            interface = interfaces[0]
            if (interface.bInterfaceNumber != 0 or interface.bAlternateSetting != 0 or
                    interface.bInterfaceClass != 0xff or
                    sorted((ep.bEndpointAddress, ep.bmAttributes & 3, ep.wMaxPacketSize)
                           for ep in interface) != [(0x01, 2, 64), (0x81, 2, 64)]):
                raise ValueError("Reader endpoints differ from captured layout")
            if device.get_active_configuration().bConfigurationValue != 1:
                raise ValueError("Expected active configuration 1")
            if device.is_kernel_driver_active(0):
                device.detach_kernel_driver(0)
                self.detached = True
            usb.util.claim_interface(device, 0)
            self.claimed = True
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, kind, value, traceback):
        if self.device is None:
            return
        try:
            if self.claimed:
                self.util.release_interface(self.device, 0)
        finally:
            try:
                if self.detached:
                    self.device.attach_kernel_driver(0)
            finally:
                self.util.dispose_resources(self.device)
                self.device = None
                self.claimed = self.detached = False
                self.setup_done = False

    def _read_exact(self, size):
        deadline = time.monotonic() + self.timeout_ms / 1000
        result = bytearray()
        while len(result) < size:
            remaining = math.ceil((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise TimeoutError("USB response deadline exceeded")
            part = bytes(self.device.read(0x81, size - len(result), timeout=remaining))
            if not part or len(part) > size - len(result):
                raise ValueError("Empty or oversized USB read")
            result.extend(part)
        return bytes(result)

    def _write(self, packet):
        if self.device.write(0x01, packet, timeout=self.timeout_ms) != len(packet):
            raise ValueError("Incomplete USB request")

    def small(self, command, payload=b"", *, allowed_events=(1,)):
        packet = small_request(command, payload)
        stage = "ready control"
        try:
            # DLL RVA 0x722b and 0x8448: setup once until CANCEL clears the
            # isSubCmdAlreadySent flag. Repeating setup mid-operation differs
            # from the vendor sequence and can invalidate transient state.
            if not self.setup_done:
                ready = bytes(self.device.ctrl_transfer(0xc0, 0xc0, 0, 0, 1, timeout=self.timeout_ms))
                if ready != b"\x5c":
                    raise ValueError("Reader is not in the observed ready state")
                self.setup_done = True
            stage = "request write"
            self._write(packet)
            stage = "response read/validation"
            result = small_response(self._read_exact(128), command, allowed_events)
            if command == 0x0c:
                self.setup_done = False
            return result
        except Exception as error:
            raise RuntimeError(f"Command 0x{command:02x}, {stage}: {error}") from error

    def connect_payload(self, host_random, host_public_key):
        if len(host_random) != 32 or len(host_public_key) != 65 or host_public_key[0] != 4:
            raise ValueError("Invalid SDCP host random/key lengths")
        # DLL RVA 0x2024: 16-byte setup, fresh-connect selector 0x11.
        setup = struct.pack("<IB11x", 2048, 0x11)
        # The DLL supplies no acknowledgement output buffer. Its payload is
        # not used; framing, command and success events remain validated.
        acknowledgement = self.small(0x77, setup)
        self.progress(f"SDCP setup acknowledged ({len(acknowledgement)} payload bytes)")
        payload = bytearray(2039)
        payload[:32] = host_random
        payload[128:193] = host_public_key
        self._write(extended_request(0x77, payload))
        self.progress("SDCP extended request sent")
        result = extended_response(self._read_exact(2048), 0x77)
        self.progress(f"SDCP extended response validated ({len(result)} payload bytes)")
        return result

    def match_payload(self, nonce):
        if len(nonce) != 32:
            raise ValueError("Authenticated matching requires a 32-byte nonce")
        # Allocate before setup: once the setup is sent, complete the transfer.
        # DLL RVA 0x8014 fills the extended dummy request with a byte counter.
        request = extended_request(0xc7, bytes(i & 0xff for i in range(2039)))
        self.progress("Authenticated match setup starting")
        acknowledgement = self.small(0xc7, nonce)
        self.progress(f"Authenticated match setup acknowledged ({len(acknowledgement)} payload bytes)")
        self._write(request)
        self.progress("Authenticated match extended request sent")
        result = extended_response(self._read_exact(2048), 0xc7)
        self.progress(f"Authenticated match extended response validated ({len(result)} payload bytes)")
        return result
