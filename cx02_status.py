#!/usr/bin/env python3
"""Read-only status reader for DNP DS620 / Citizen CX-02 dye-sub printers.

Companion to ds620_updater — this NEVER writes to the printer. It sends only
the PSTATUS query and a handful of PINFO/PMNT read queries, decodes the
status code, and prints a human verdict (idle / ribbon-end / paper-end /
error). Use it to diagnose a stuck CUPS queue without flashing anything.

Requires root (claims the USB interface) and CUPS stopped (CUPS holds the
device otherwise). Safe to Ctrl-C at any time — it only ever reads.

    sudo systemctl stop cups
    sudo python3 cx02_status.py
    sudo systemctl start cups
"""

from __future__ import annotations

import sys

try:
    import usb.core
    import usb.util
except ImportError:
    print("Error: pyusb not installed. Run: pip install pyusb", file=sys.stderr)
    sys.exit(2)

# (VID, PID) -> model. Mirrors ds620_updater DEVICE_TABLE; the unit on kiosk
# 109 is 0x1343:0x000a (CX-02).
DEVICE_TABLE = {
    (0x1452, 0x8B01): "DS620",
    (0x1452, 0x8B02): "DS620 (alt)",
    (0x1452, 0x9001): "DS820",
    (0x1452, 0x9401): "DS820DX",
    (0x1343, 0x0003): "DS40",
    (0x1343, 0x0004): "DS80",
    (0x1343, 0x0005): "DS-RX1",
    (0x1343, 0x0006): "CW-02",
    (0x1343, 0x000A): "CX-02",
    (0x1343, 0xFFFF): "QW410",
}

ESC = 0x1B
FRAME_SIZE = 32
FULL_CMD_SIZE = 31
SIZE_FIELD_LEN = 8
TIMEOUT_MS = 5000

# Raw PSTATUS integer -> (label, is_blocking). From the decompiled GetStatus
# switch table (cspstat64.dll). Blocking states need operator action.
STATUS_TABLE = {
    0: ("idle (usually idle)", False),
    1: ("ready", False),
    2: ("cover open", True),
    3: ("cover open", True),
    500: ("ribbon error", True),
    510: ("ribbon error 2", True),
    900: ("cover open", True),
    1000: ("printing", False),
    1010: ("printing + warning", False),
    1011: ("printing + warning 2", False),
    1100: ("PAPER END (media out)", True),
    1200: ("RIBBON END (ribbon out)", True),
    1300: ("feeding", False),
    1400: ("cutting", False),
    1500: ("paper end during print", True),
    1600: ("ribbon end during print", True),
    2000: ("error: general", True),
    2010: ("error: motor", True),
    2100: ("error: head", True),
    2200: ("error: cutter", True),
    2300: ("error: paper jam", True),
    2400: ("error: ribbon break", True),
    2500: ("error: paper feed", True),
}

# Strict allowlist — the ONLY frames this tool may ever emit. Anything that
# mutates the printer (PFW_*, PTBL_WT*, PCNTRL, PIMAGE) is absent by design.
READ_QUERIES = [
    ("PSTATUS", "Status code"),
    ("PINFO  FVER", "Firmware version"),
    ("PINFO  SERIAL_NUMBER", "Serial number"),
    ("PINFO  UNIT_STATUS", "Unit status"),
    ("PINFO  MEDIA", "Media type"),
    ("PINFO  MEDIA_CLASS", "Media class"),
    ("PINFO  MQTY", "Media remaining"),
    ("PINFO  RQTY", "Remaining qty (high)"),
    ("PINFO  FREE_PBUFFER", "Free print buffer"),
    ("PINFO  SENSOR", "Sensor readings"),
    ("PMNT_RDCOUNTER_LIFE", "Lifetime counter"),
]


def build_frame(cmd_text: str) -> bytes:
    encoded = cmd_text.encode("ascii")
    if len(encoded) > FULL_CMD_SIZE:
        raise ValueError(f"command too long: {cmd_text!r}")
    return bytes([ESC]) + encoded.ljust(FULL_CMD_SIZE)


def find_printer():
    for dev in usb.core.find(find_all=True):
        model = DEVICE_TABLE.get((dev.idVendor, dev.idProduct))
        if model:
            return dev, model
    return None, None


def claim(dev):
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (usb.core.USBError, NotImplementedError):
        pass
    dev.set_configuration()
    intf = dev.get_active_configuration()[(0, 0)]
    ep_out = usb.util.find_descriptor(
        intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
    )
    ep_in = usb.util.find_descriptor(
        intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
    )
    if not ep_out or not ep_in:
        raise RuntimeError("bulk endpoints not found")
    # Drain stale bytes so a query reads its own response.
    try:
        for _ in range(64):
            ep_in.read(1024, timeout=100)
    except usb.core.USBError:
        pass
    return ep_out, ep_in


def query(ep_out, ep_in, cmd_text: str) -> bytes | None:
    ep_out.write(build_frame(cmd_text))
    raw_len = bytes(ep_in.read(SIZE_FIELD_LEN, timeout=TIMEOUT_MS))
    if len(raw_len) != SIZE_FIELD_LEN:
        return None
    try:
        length = int(raw_len.decode("ascii").strip().strip("\x00"))
    except ValueError:
        return None
    if length <= 0:
        return b""
    if length > 1_000_000:
        return None
    return bytes(ep_in.read(length, timeout=TIMEOUT_MS)).rstrip(b"\x00")


def decode_status(raw: bytes | None) -> str:
    if not raw:
        return "no response"
    s = raw.decode("ascii", errors="replace").strip()
    if s.startswith("FU"):
        return f"flash-update mode (FU{s[2:]})"
    try:
        code = int(s)
    except ValueError:
        return f"unparseable status: {s!r}"
    label, blocking = STATUS_TABLE.get(code, (f"unknown code {code}", True))
    return f"{code} -> {label}" + ("   [BLOCKING — needs operator action]" if blocking else "")


def main() -> int:
    dev, model = find_printer()
    if not dev:
        print("No DNP/Citizen printer found on USB.", file=sys.stderr)
        print("If CUPS is running it may hold the device: sudo systemctl stop cups", file=sys.stderr)
        return 1

    print(f"Found {model}: VID=0x{dev.idVendor:04x} PID=0x{dev.idProduct:04x} "
          f"(bus {dev.bus} addr {dev.address})")
    try:
        ep_out, ep_in = claim(dev)
    except usb.core.USBError as e:
        print(f"USB claim failed: {e}", file=sys.stderr)
        print("Need root + CUPS stopped: sudo systemctl stop cups; sudo python3 cx02_status.py", file=sys.stderr)
        return 1

    print(f"USB OK: OUT=0x{ep_out.bEndpointAddress:02x} IN=0x{ep_in.bEndpointAddress:02x}\n")

    status_raw = None
    for cmd, label in READ_QUERIES:
        try:
            r = query(ep_out, ep_in, cmd)
        except usb.core.USBError as e:
            print(f"  {label:22s}: <USB error: {e}>")
            continue
        if cmd == "PSTATUS":
            status_raw = r
        shown = r.decode("ascii", errors="replace").strip() if r else "<no data>"
        print(f"  {label:22s}: {shown}")

    print(f"\n  VERDICT: {decode_status(status_raw)}")

    usb.util.dispose_resources(dev)
    try:
        dev.attach_kernel_driver(0)
    except (usb.core.USBError, NotImplementedError):
        pass  # CUPS' libusb backend re-opens on `systemctl start cups`
    return 0


if __name__ == "__main__":
    sys.exit(main())
