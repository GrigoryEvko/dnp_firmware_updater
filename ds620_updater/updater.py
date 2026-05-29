#!/usr/bin/env python3
"""
DS620A Firmware Updater for Linux
Protocol reverse-engineered from cspstat64.dll and CSJCX2lm.dll via IDA Pro decompilation.

Wire format (from cspstat64.dll sprintf_s calls):
  - All command frames are exactly 32 bytes: ESC (0x1B) + 31 ASCII chars, space-padded
  - Query response: 8-byte ASCII decimal length + N bytes data
  - Data write: 32-byte header (ESC + cmd[23] + size[8]) + payload (NO trailer)
  - NO CRLF termination on commands

USB access: bulk OUT + bulk IN endpoints on printer class interface.
"""

import sys
import os
import time
import argparse
import logging
import subprocess
import signal
import atexit
from pathlib import Path
from datetime import datetime

try:
    import usb.core
    import usb.util
except ImportError:
    print("Error: pyusb not installed. Please run: pip install pyusb")
    sys.exit(1)

# USB Device IDs (from cspstat64.dll SetupDi enumeration strings)
# DS620/CX-02 use vendor 0x1452, older DNP models use 0x1343
DEVICE_TABLE = {
    (0x1452, 0x8b01): "DS620",
    (0x1452, 0x8b02): "DS620 (alt)",
    (0x1452, 0x9001): "DS820",
    (0x1452, 0x9201): "DS820 (alt)",
    (0x1452, 0x9301): "DS820 (v3)",
    (0x1452, 0x9401): "DS820DX",
    (0x1343, 0x0003): "DS40",
    (0x1343, 0x0004): "DS80",
    (0x1343, 0x0005): "DS-RX1",
    (0x1343, 0x0006): "CW-02",
    (0x1343, 0x0007): "DP-TC",
    (0x1343, 0x0008): "DS80DUP",
    (0x1343, 0x000a): "CX-02",
    (0x1343, 0xFFFF): "QW410",
    (0x1343, 0x1001): "DI-RS1",
}

# Protocol constants (from cspstat64.dll)
ESC = 0x1B
FRAME_SIZE = 32          # Every command frame is exactly 32 bytes
CMD_FIELD_SIZE = 23      # Command text portion in data frames (before 8-byte size)
FULL_CMD_SIZE = 31       # Command text portion in non-data frames (ESC + 31 = 32)
SIZE_FIELD_LEN = 8       # ASCII decimal size field length
CHUNK_SIZE = 0x100000    # 1 MB — max WriteFile chunk in cspstat64.dll sub_180017160

# Timing (from .NET updater: WAIT_CHKSTS=2000, WAIT_CHMODE=4000, WAIT_UPDATE=15000)
TIMEOUT_DEFAULT = 5000   # 5 seconds for normal commands
TIMEOUT_UPDATE = 30000   # 30 seconds for firmware update operations
TIMEOUT_FLASH = 120000   # 2 minutes for flash programming
WAIT_CHMODE = 4.0        # Seconds to wait after entering update mode
WAIT_POST_TRANSFER = 15.0  # Seconds to wait after firmware transfer before polling
WAIT_POLL_INTERVAL = 2.0   # Seconds between status polls
MODE_RETRY_COUNT = 30    # Max retries waiting for FLSHPROG_IDLE (30 × 1s = 30s)
UPDATE_RETRY_COUNT = 240 # Max retries waiting for flash complete (240 × 2s = 8min, spec says up to 5min)

# Printer status codes (from CspStat.cs constants)
CVS_USUALLY_IDLE = 0x10001
CVS_USUALLY_PAPER_END = 0x10008
CVS_USUALLY_RIBBON_END = 0x10010
CVS_FLSHPROG_IDLE = 0x100001
CVS_FLSHPROG_WRITING = 0x100002
CVS_FLSHPROG_FINISHED = 0x100004
CVS_FLSHPROG_DATA_ERR1 = 0x100008
CVS_FLSHPROG_DEVICE_ERR1 = 0x100010
CVSTATUS_ERROR = -0x80000000


def _build_frame(cmd_text: str) -> bytes:
    """Build 32-byte command frame for non-data commands.

    Format: ESC + cmd_text padded to 31 chars with spaces = 32 bytes total.
    Used for: PSTATUS, PINFO queries, PCNTRL commands, PFW_UPDFLASH_REWRITE, etc.
    """
    encoded = cmd_text.encode('ascii')
    if len(encoded) > FULL_CMD_SIZE:
        raise ValueError(f"Command '{cmd_text}' too long: {len(encoded)} > {FULL_CMD_SIZE}")
    return bytes([ESC]) + encoded.ljust(FULL_CMD_SIZE)


def _build_data_frame(cmd_text: str, data_len: int) -> bytes:
    """Build 32-byte header for data write commands.

    Format: ESC + cmd_text[23 chars, space-padded] + 8-digit ASCII size = 32 bytes.
    Followed by: payload bytes only (NO trailer — verified against sub_180017870).
    Used for: PFW_UPDFLASH_PROGRAM, PTBL_WTCTRLD_UPDATE_CW, etc.
    """
    if data_len < 0 or data_len > 99_999_999:
        raise ValueError(f"Data length {data_len} out of range [0, 99999999]")
    encoded = cmd_text.encode('ascii')
    if len(encoded) > CMD_FIELD_SIZE:
        raise ValueError(f"Data command '{cmd_text}' too long: {len(encoded)} > {CMD_FIELD_SIZE}")
    cmd_part = encoded.ljust(CMD_FIELD_SIZE)
    size_part = f"{data_len:08d}".encode('ascii')
    return bytes([ESC]) + cmd_part + size_part


class DS620Updater:
    def __init__(self, firmware_path: str, cwd_dir: str, log_file: str = None):
        self.firmware_path = Path(firmware_path)
        self.cwd_dir = Path(cwd_dir)
        self.device = None
        self.ep_out = None
        self.ep_in = None
        self.cups_was_running = False
        self.update_in_progress = False
        self.start_time = datetime.now()
        self.setup_logging(log_file)
        self.setup_signal_handlers()

    # ── Logging & lifecycle ──────────────────────────────────────────────

    def setup_logging(self, log_file: str):
        self.logger = logging.getLogger(__name__)
        if self.logger.handlers:
            return  # Already configured (prevents duplicate handlers on re-instantiation)
        root_debug = logging.getLogger().level == logging.DEBUG
        self.logger.setLevel(logging.DEBUG if (log_file or root_debug) else logging.INFO)

        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG if logging.getLogger().level == logging.DEBUG else logging.INFO)
        console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console)

        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
            self.logger.addHandler(fh)

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)
        atexit.register(self.cleanup)

    def _on_signal(self, signum, frame):
        self.logger.warning("\nReceived interrupt signal!")
        if self.update_in_progress:
            self.logger.error("UPDATE IN PROGRESS — interrupting may BRICK the printer!")
            self.logger.error("Press Ctrl+C again within 5s to force quit...")
            signal.signal(signal.SIGINT, lambda s, f: (self.cleanup(), sys.exit(1)))
            time.sleep(5)
            signal.signal(signal.SIGINT, self._on_signal)
        else:
            self.cleanup()
            sys.exit(1)

    def cleanup(self):
        self.logger.info("Cleaning up...")
        if self.device:
            try:
                usb.util.dispose_resources(self.device)
            except Exception:
                pass
            self.device = None
            self.ep_out = None
            self.ep_in = None
        if self.cups_was_running:
            self.cups_was_running = False  # Prevent double restart
            self.logger.info("Restarting CUPS service...")
            try:
                subprocess.run(['sudo', 'systemctl', 'start', 'cups'],
                               capture_output=True, check=True, timeout=30)
                subprocess.run(['sudo', 'systemctl', 'start', 'cups-browsed'],
                               capture_output=True, timeout=30)
                self.logger.info("CUPS restarted")
            except Exception as e:
                self.logger.error(f"Failed to restart CUPS: {e}")
                self.logger.error("Run manually: sudo systemctl start cups")

    # ── USB discovery & setup ────────────────────────────────────────────

    def find_printer(self) -> bool:
        """Find DS620/CX-02 printer via USB, checking all known VID/PID pairs."""
        cups_running, printer_in_cups, cups_name = self._check_cups()

        if printer_in_cups:
            self.logger.warning("=" * 60)
            self.logger.warning("DS620/CX-02 is configured in CUPS — may block USB access.")
            self.logger.warning(f"  sudo systemctl stop cups")
            if cups_name:
                self.logger.warning(f"  sudo lpadmin -x {cups_name}")
            self.logger.warning("=" * 60)
            if os.geteuid() != 0:
                self.logger.error("Not running as root. Try: sudo ...")

        for (vid, pid), model in DEVICE_TABLE.items():
            self.device = usb.core.find(idVendor=vid, idProduct=pid)
            if self.device:
                self.logger.info(f"Found {model}: VID=0x{vid:04x} PID=0x{pid:04x}")
                self.vendor_id = vid
                self.product_id = pid
                self.model_name = model
                return True

        self.logger.error("Printer not found. Checked VIDs: 0x1452 (DS620/CX-02), 0x1343 (DNP legacy)")
        if cups_running:
            self.logger.error("CUPS is running and may be claiming the device. Try: sudo systemctl stop cups")
        return False

    def _check_cups(self):
        cups_running = False
        printer_in_cups = False
        cups_name = None
        try:
            r = subprocess.run(['systemctl', 'is-active', 'cups'], capture_output=True, text=True, timeout=10)
            cups_running = r.stdout.strip() == 'active'
            if cups_running:
                r = subprocess.run(['lpstat', '-v'], capture_output=True, text=True, timeout=10)
                for line in r.stdout.split('\n'):
                    if any(k in line.lower() for k in ['ds620', 'cx-02', 'dnp', 'citizen']):
                        printer_in_cups = True
                        if line.startswith('device for '):
                            cups_name = line.split(':')[0].replace('device for ', '')
        except Exception:
            pass
        return cups_running, printer_in_cups, cups_name

    def setup_usb(self) -> bool:
        """Detach kernel driver, claim interface, find bulk endpoints."""
        try:
            self._unbind_usblp()

            if self.device.is_kernel_driver_active(0):
                self.device.detach_kernel_driver(0)

            self.device.set_configuration()
            cfg = self.device.get_active_configuration()
            intf = cfg[(0, 0)]

            self.ep_out = usb.util.find_descriptor(
                intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
            self.ep_in = usb.util.find_descriptor(
                intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)

            if not self.ep_out or not self.ep_in:
                raise RuntimeError("Could not find USB bulk endpoints")

            self.logger.info(f"USB OK: OUT=0x{self.ep_out.bEndpointAddress:02x} IN=0x{self.ep_in.bEndpointAddress:02x}")
            self._drain_input()
            return True
        except Exception as e:
            self.logger.error(f"USB setup failed: {e}")
            return False

    def _unbind_usblp(self):
        """Unbind usblp kernel driver from the printer interface."""
        import glob
        bus, addr = self.device.bus, self.device.address
        sysfs = "/sys/bus/usb/devices/"
        for devpath in glob.glob(f"{sysfs}{bus}-*"):
            if not os.path.isdir(devpath):
                continue
            try:
                devnum_file = os.path.join(devpath, "devnum")
                if os.path.exists(devnum_file):
                    with open(devnum_file) as f:
                        if int(f.read().strip()) == addr:
                            iface = os.path.basename(devpath) + ":1.0"
                            unbind = "/sys/bus/usb/drivers/usblp/unbind"
                            if os.path.exists(unbind):
                                with open(unbind, 'w') as uf:
                                    uf.write(iface + "\n")
                                self.logger.info(f"Unbound usblp from {iface}")
                                time.sleep(0.5)
                            return
            except Exception:
                continue

    def _reconnect_usb(self) -> bool:
        """Re-discover and re-setup USB after device re-enumeration.

        Called when the printer reboots (e.g., entering bootloader after
        PFW_UPDFLASH_REWRITE, or rebooting after flash completion).
        The device gets a new USB bus address, invalidating old handles.
        """
        try:
            # Dispose old stale handles
            if self.device:
                try:
                    usb.util.dispose_resources(self.device)
                except Exception:
                    pass
            self.device = None
            self.ep_out = None
            self.ep_in = None

            # Re-find the printer
            if not self.find_printer():
                return False
            if not self.setup_usb():
                return False
            return True
        except Exception as e:
            self.logger.debug(f"  USB reconnect failed: {e}")
            return False

    def _drain_input(self):
        """Drain any stale data from the IN endpoint (max 256KB)."""
        try:
            for _ in range(256):
                self.ep_in.read(1024, timeout=100)
        except usb.core.USBTimeoutError:
            pass

    # ── Wire protocol primitives ─────────────────────────────────────────
    # Based on cspstat64.dll: sub_180017620 (query), sub_180017870 (write)

    def _usb_write_with_retry(self, data: bytes, retries: int = 3, label: str = "write"):
        """Write to USB OUT endpoint with retry on timeout.

        The printer may temporarily NAK writes while busy processing a
        previous command (e.g., CWD data write before version set).
        [Errno 110] Operation timed out = kernel USB write timeout.
        """
        for attempt in range(retries):
            try:
                self.ep_out.write(data)
                return
            except usb.core.USBError as e:
                if attempt < retries - 1 and e.errno == 110:  # ETIMEDOUT
                    wait = (attempt + 1) * 2.0
                    self.logger.warning(f"  {label}: write timeout, retrying in {wait}s ({attempt+1}/{retries})...")
                    time.sleep(wait)
                else:
                    raise

    def send_command(self, cmd_text: str):
        """Send a 32-byte command frame (no data, no response expected).

        Used for: PFW_UPDFLASH_REWRITE, PCNTRL PRINTER_RESET, etc.
        """
        frame = _build_frame(cmd_text)
        if len(frame) != FRAME_SIZE:
            raise ValueError(f"Frame size {len(frame)} != {FRAME_SIZE}")
        self.logger.debug(f"CMD> {cmd_text!r}  [{frame.hex()}]")
        self._usb_write_with_retry(frame, retries=3, label=cmd_text)

    def query_command(self, cmd_text: str, timeout: int = TIMEOUT_DEFAULT) -> bytes:
        """Send 32-byte command, read 8-byte ASCII length + data response.

        Protocol (cspstat64.dll sub_180017620):
          Host -> Printer: [32-byte frame]
          Printer -> Host: [8-byte ASCII length][N bytes data]
        """
        frame = _build_frame(cmd_text)
        if len(frame) != FRAME_SIZE:
            raise ValueError(f"Frame size {len(frame)} != {FRAME_SIZE}")
        self.logger.debug(f"QRY> {cmd_text!r}")

        try:
            self.ep_out.write(frame)

            # Read 8-byte ASCII length prefix
            raw_len = bytes(self.ep_in.read(SIZE_FIELD_LEN, timeout=timeout))
            if len(raw_len) != SIZE_FIELD_LEN:
                self.logger.debug(f"  short length read: got {len(raw_len)} bytes, expected {SIZE_FIELD_LEN}")
                return None
            length = int(raw_len.decode('ascii').strip().strip('\x00'))
            self.logger.debug(f"  response length: {length} (raw: {raw_len!r})")

            if length <= 0:
                return b''
            if length > 1_000_000:
                self.logger.error(f"  response length {length} exceeds 1MB sanity limit")
                return None

            # Read exactly N bytes of response data
            # Strip trailing NUL padding — printer may pad ASCII responses with \x00.
            # str.strip() only removes whitespace, NOT NUL, so downstream int() and
            # equality comparisons fail on NUL-contaminated strings.
            data = bytes(self.ep_in.read(length, timeout=timeout)).rstrip(b'\x00')
            self.logger.debug(f"  response data: {data!r}")
            return data

        except usb.core.USBTimeoutError:
            self.logger.debug(f"  timeout (no response)")
            return None
        except usb.core.USBError as e:
            # USB device error — printer may have rebooted (re-enumerated)
            self.logger.debug(f"  USB error (device may have rebooted): {e}")
            return None
        except (ValueError, UnicodeDecodeError) as e:
            self.logger.debug(f"  parse error: {e}")
            return None

    def send_data_command(self, cmd_text: str, data: bytes):
        """Send command with payload: [32-byte header][data chunks]. No trailer.

        Protocol (cspstat64.dll sub_180017870 / SetFirmwDataWrite):
          Block 0: ESC + cmd_text[23 chars] + 8-digit ASCII size = 32 bytes
          Block 1: payload data (chunked at 1MB)
          Block 2: (NULL/0 — loop terminates, NO trailer sent)

        Verified: sub_180017870 iterates up to 4 blocks, breaks when size=0.
        SetFirmwDataWrite sets block 2 = {data, len}, block 3 = {NULL, 0}.
        No 4-byte LE trailer exists in the original protocol.
        sub_180017870 is write-only — never reads a response after data writes.
        """
        header = _build_data_frame(cmd_text, len(data))
        if len(header) != FRAME_SIZE:
            raise ValueError(f"Data header size {len(header)} != {FRAME_SIZE}")

        self.logger.debug(f"DAT> {cmd_text!r}  size={len(data)}  [{header.hex()}]")

        # Send 32-byte header (with retry — printer may be busy processing previous command)
        self._usb_write_with_retry(header, retries=3, label=f"{cmd_text} header")

        # Send payload in 1MB chunks (cspstat64.dll sub_180017160 chunk limit)
        total_sent = 0
        t0 = time.time()
        while total_sent < len(data):
            chunk = data[total_sent:total_sent + CHUNK_SIZE]
            self.ep_out.write(chunk)
            total_sent += len(chunk)

            elapsed = time.time() - t0
            if elapsed > 0 and total_sent < len(data):
                pct = total_sent / len(data) * 100
                rate = total_sent / elapsed / 1024
                eta = (len(data) - total_sent) / (total_sent / elapsed)
                self.logger.info(f"  {pct:.0f}%  {total_sent // 1024}K / {len(data) // 1024}K  "
                                 f"{rate:.0f} KB/s  ETA {eta:.0f}s")

        elapsed = time.time() - t0
        rate = f"{len(data) / elapsed / 1024:.0f} KB/s" if elapsed > 0 else "instant"
        self.logger.info(f"  Sent {len(data)} bytes in {elapsed:.1f}s ({rate})")

    # ── Printer info queries ─────────────────────────────────────────────

    def get_device_id(self):
        """Read IEEE 1284 Device ID via USB printer class control transfer."""
        try:
            data = self.device.ctrl_transfer(0xA1, 0x00, 0, 0, 1024, timeout=1000)
            if data and len(data) > 2:
                id_len = (data[0] << 8) | data[1]
                id_str = data[2:2 + id_len].decode('ascii', errors='ignore')
                self.logger.info(f"Device ID: {id_str}")
                return id_str
        except Exception as e:
            self.logger.debug(f"GET_DEVICE_ID failed: {e}")
        return None

    def get_printer_info(self):
        """Query printer firmware version, serial, status."""
        self.logger.info("Querying printer info...")

        r = self.query_command("PSTATUS")
        if r:
            self.logger.info(f"Status: {r.decode('ascii', errors='replace').strip()}")

        for cmd, label in [
            ("PINFO  FVER",           "Firmware version"),
            ("PINFO  SERIAL_NUMBER",  "Serial number"),
            ("PINFO  UNIT_STATUS",    "Unit status"),
            ("PINFO  MEDIA",          "Media type"),
            ("PINFO  MEDIA_CLASS",    "Media class"),
            ("PINFO  MQTY",           "Media remaining"),
            ("PINFO  FREE_PBUFFER",   "Free print buffer"),
        ]:
            r = self.query_command(cmd)
            if r:
                self.logger.info(f"  {label}: {r.decode('ascii', errors='replace').strip()}")

        # Read firmware version via PTBL path too
        r = self.query_command("PTBL_RDVersion         00000000")
        if r:
            self.logger.info(f"  FW version (PTBL): {r.decode('ascii', errors='replace').strip()}")

    def check_cwd_versions(self):
        """Query CWD version and checksum for each resolution.

        CWD IDs are 300/600/610 (from cspstat64.dll GetColorDataVersionRes).
        """
        self.logger.info("Checking CWD versions...")
        for res_id in ["300", "600", "610"]:
            ver = self.query_command(f"PTBL_RDCWD{res_id}_Version  00000000")
            chk = self.query_command(f"PTBL_RDCWD{res_id}_Checksum 00000000")
            ver_s = ver.decode('ascii', errors='replace').strip() if ver else "N/A"
            chk_s = chk.decode('ascii', errors='replace').strip() if chk else "N/A"
            self.logger.info(f"  CWD{res_id}: version={ver_s}  checksum={chk_s}")

        # Global CWD checksum
        r = self.query_command("PMNT_RDCTRLD_CHKSUM    00000000")
        if r:
            self.logger.info(f"  Global CWD checksum: {r.decode('ascii', errors='replace').strip()}")

    def get_life_counter(self):
        r = self.query_command("PMNT_RDCOUNTER_LIFE")
        if r:
            self.logger.info(f"  Life counter: {r.decode('ascii', errors='replace').strip()}")

    # ── Firmware update sequence ─────────────────────────────────────────
    # Matches .NET updater: CvSetFirmwUpdateMode -> CvSetFirmwDataWrite -> waitUpdate

    def get_status_code(self) -> int:
        """Query PSTATUS and translate raw response to bitmask status code.

        Reimplements GetStatus (0x180001cd0) from cspstat64.dll which:
        1. Sends PSTATUS query
        2. Checks for "FU" prefix (flash update mode) → parses number after "FU"
        3. Otherwise parses as integer → maps through switch table
        Returns CVSTATUS_ERROR on failure.
        """
        r = self.query_command("PSTATUS")
        if not r:
            return CVSTATUS_ERROR

        status_str = r.decode('ascii', errors='replace').strip()
        self.logger.debug(f"  raw status: {status_str!r}")

        # Flash update mode: "FU" prefix (from GetStatus strncmp check)
        if status_str.startswith("FU"):
            try:
                fu_num = int(status_str[2:])
            except ValueError:
                return CVSTATUS_ERROR
            fu_map = {
                1: CVS_FLSHPROG_IDLE,       # 0x100001
                2: CVS_FLSHPROG_WRITING,     # 0x100002
                3: CVS_FLSHPROG_FINISHED,    # 0x100004
                100: CVS_FLSHPROG_DATA_ERR1, # 0x100008
                101: CVS_FLSHPROG_DATA_ERR1, # 0x100008 (same bucket)
                200: CVS_FLSHPROG_DEVICE_ERR1,  # 0x100010
                300: 0x100020,               # flash error 300
            }
            return fu_map.get(fu_num, CVSTATUS_ERROR)

        # Normal mode: integer status → bitmask (from GetStatus switch table)
        # Every value verified against decompiled GetStatus_0x180001cd0.c
        try:
            raw = int(status_str)
        except ValueError:
            self.logger.debug(f"  unparseable status: {status_str!r}")
            return CVSTATUS_ERROR

        status_map = {
            0: 0x10001,     # CVS_USUALLY_IDLE
            1: 0x10002,     # ready
            2: 0x10080,     # cover open
            3: 0x10100,     # cover open (alternate)
            500: 0x10020,   # ribbon error
            510: 0x10040,   # ribbon error 2
            900: 0x10080,   # cover open
            1000: 0x20001,  # printing
            1010: 0x20020,  # printing + warning
            1011: 0x20080,  # printing + warning 2
            1100: 0x10008,  # paper end
            1200: 0x10010,  # ribbon end
            1300: 0x20002,  # feeding
            1400: 0x20004,  # cutting
            1500: 0x20008,  # paper end during print
            1600: 0x20010,  # ribbon end during print
            2000: 0x40001,  # error: general
            2010: 0x40800,  # error: motor
            2100: 0x40002,  # error: head
            2200: 0x40004,  # error: cutter
            2300: 0x40008,  # error: paper jam
            2400: 0x40010,  # error: ribbon break
            2500: 0x40020,  # error: paper feed
            2600: 0x40040,  # error: head temp
            2610: 0x40200,  # error: voltage
            2700: 0x40080,  # error: media
            2800: 0x40100,  # error: hardware
            2900: 0x40400,  # error: firmware
            3000: 0x80001,  # fatal error
            5017: 0x200011, # maintenance mode
            6000: 0x20040,  # cooling
        }
        result = status_map.get(raw)
        if result is not None:
            return result

        # Extended 5xxx codes (discrete switch table from GetStatus)
        extended_5xxx = {
            5019: 0x200013, 5023: 0x200017, 5027: 0x20001B, 5030: 0x20001E,
            5049: 0x200031, 5065: 0x200041, 5081: 0x200051, 5097: 0x200061,
            5113: 0x200071, 5129: 0x200081, 5145: 0x200091, 5161: 0x2000A1,
            5177: 0x2000B1, 5193: 0x2000C1, 5209: 0x2000D1, 5241: 0x2000F1,
        }
        if raw in extended_5xxx:
            return extended_5xxx[raw]

        # Extended 6xxx codes (power-of-2 pattern from GetStatus)
        extended_6xxx = {
            6010: 0x400001, 6020: 0x400002, 6030: 0x400004, 6040: 0x400008,
            6050: 0x400010, 6060: 0x400020, 6070: 0x400040,
        }
        if raw in extended_6xxx:
            return extended_6xxx[raw]

        self.logger.debug(f"  unknown raw status {raw}")
        return CVSTATUS_ERROR

    def enter_update_mode(self) -> bool:
        """Step 1: PFW_UPDFLASH_REWRITE — put printer in flash rewrite mode.

        From Form1.PRINTER_FW (line 3055):
          CvSetFirmwUpdateMode(port)  → sends PFW_UPDFLASH_REWRITE
          SleepDoEvent(4000)          → wait 4 seconds
          Loop CvGetStatus(port) until == CVS_FLSHPROG_IDLE (0x100001)
          Retry up to 30 times with 1s sleep between attempts.
        """
        # Check if printer is ALREADY in flash mode (e.g., from a previous
        # interrupted attempt). If so, skip REWRITE to avoid a second reboot.
        status = self.get_status_code()
        if status == CVS_FLSHPROG_IDLE:
            self.logger.info("Printer already in flash program mode (FLSHPROG_IDLE) — skipping REWRITE")
            return True

        self.logger.info("Entering firmware update mode (FLASH_REWRITE)...")
        self.send_command("PFW_UPDFLASH_REWRITE")

        self.logger.info(f"  Waiting {WAIT_CHMODE}s for mode change...")
        time.sleep(WAIT_CHMODE)

        # The printer reboots into its bootloader after REWRITE, causing USB
        # re-enumeration. The old device/endpoint handles become stale ([Errno 19]).
        # On Windows, CreateFileA handles survive re-enumeration transparently.
        # On Linux with pyusb, we must re-discover the device.
        reconnected = False

        # Poll status until CVS_FLSHPROG_IDLE
        for attempt in range(MODE_RETRY_COUNT):
            time.sleep(1.0)
            status = self.get_status_code()
            self.logger.debug(f"  Status poll {attempt + 1}/{MODE_RETRY_COUNT}: 0x{status & 0xFFFFFFFF:08x}")

            if status == CVS_FLSHPROG_IDLE:
                self.logger.info("Printer in flash program mode (FLSHPROG_IDLE)")
                return True
            if status == CVSTATUS_ERROR and not reconnected:
                # Device likely re-enumerated — try to re-acquire USB
                self.logger.info("  USB device lost — attempting reconnect (printer rebooted into bootloader)...")
                time.sleep(2.0)  # Extra time for USB re-enumeration
                if self._reconnect_usb():
                    reconnected = True
                    self.logger.info("  USB reconnected to bootloader")
                else:
                    self.logger.debug("  Reconnect failed, will retry...")
                continue
            if status == CVSTATUS_ERROR:
                continue

        self.logger.error(f"Failed to enter update mode after {MODE_RETRY_COUNT} attempts")
        return False

    def send_firmware(self) -> bool:
        """Step 2: PFW_UPDFLASH_PROGRAM — send S-Record firmware data.

        From Form1.PRINTER_FW (line 3082):
          SetFirmwDataWrite(port, array, num)
          → cspstat64.dll sends PFW_UPDFLASH_PROGRAM + 8-digit size + data (no trailer)

        Firmware data is padded to 32-byte boundary with zeros (Form1 line 3041-3049).
        """
        self.logger.info(f"Sending firmware: {self.firmware_path}")

        with open(self.firmware_path, 'rb') as f:
            firmware = f.read()

        # Pad to 32-byte boundary with zeros (from Form1.PRINTER_FW line 3041)
        remainder = len(firmware) % 32
        if remainder != 0:
            pad = 32 - remainder
            firmware += b'\x00' * pad
            self.logger.debug(f"  Padded {pad} bytes to 32-byte boundary")

        self.logger.info(f"  Size: {len(firmware)} bytes ({len(firmware) / 1024 / 1024:.1f} MB)")

        self.send_data_command("PFW_UPDFLASH_PROGRAM", firmware)
        return True

    def wait_for_flash(self) -> bool:
        """Step 3: Poll CvGetStatus until printer returns to normal idle.

        From Form1.PRINTER_FW (lines 3091-3146):
          SleepDoEvent(15000)  → wait 15 seconds before first poll
          Loop CvGetStatus(port) for up to 90 iterations × 2s = 3 minutes:
            - CVS_USUALLY_IDLE (0x10001): success — printer rebooted to normal
            - CVS_USUALLY_PAPER_END (0x10008): success (paper removed during update)
            - CVS_USUALLY_RIBBON_END (0x10010): success (ribbon end)
            - Status > 0x20001 and < 0x100001: setting/hardware error → fail
            - Status > 0x100004: flash programming error → fail
        """
        self.logger.info(f"Waiting {WAIT_POST_TRANSFER}s for flash write to begin...")
        time.sleep(WAIT_POST_TRANSFER)

        self.logger.info(f"Polling status (up to {UPDATE_RETRY_COUNT} × {WAIT_POLL_INTERVAL}s)...")
        reconnected = False
        consecutive_errors = 0

        for attempt in range(UPDATE_RETRY_COUNT):
            time.sleep(WAIT_POLL_INTERVAL)
            status = self.get_status_code()
            s = status & 0xFFFFFFFF
            self.logger.debug(f"  Poll {attempt + 1}/{UPDATE_RETRY_COUNT}: status=0x{s:08x}")

            # Success conditions — printer returned to normal operation
            if status in (CVS_USUALLY_IDLE, CVS_USUALLY_PAPER_END, CVS_USUALLY_RIBBON_END):
                self.logger.info(f"Flash complete — printer idle (status=0x{s:08x})")
                return True

            # Error conditions from .NET updater
            if status > 0x20001 and status < CVS_FLSHPROG_IDLE:
                self.logger.error(f"Printer error during flash (status=0x{s:08x})")
                return False
            if status > CVS_FLSHPROG_FINISHED and status != CVSTATUS_ERROR:
                self.logger.error(f"Flash programming error (status=0x{s:08x})")
                return False

            # USB re-enumeration handling — printer reboots after flash completion,
            # causing [Errno 19]. Re-discover the device.
            if status == CVSTATUS_ERROR:
                consecutive_errors += 1
                if consecutive_errors >= 5 and not reconnected:
                    self.logger.info("  USB lost for 10s — printer may have rebooted, reconnecting...")
                    time.sleep(3.0)
                    if self._reconnect_usb():
                        reconnected = True
                        consecutive_errors = 0
                        self.logger.info("  USB reconnected")
            else:
                consecutive_errors = 0

        self.logger.error(f"Flash timed out after {UPDATE_RETRY_COUNT * WAIT_POLL_INTERVAL:.0f}s")
        return False

    def _send_cwd_version(self, fname: str):
        """Send CWD version via PTBL_WTVersion with 16-byte padded data.

        SetColorDataVersion (0x180005420) in cspstat64.dll:
        - Rejects strings > 32 bytes
        - Pads data to 16-byte boundary: if (len & 0xF) != 0: len = (len+16) & 0xFFFFFFF0
        - Sends: ESC + "PTBL_WT" + "Version         " + 8-digit padded size + padded data
        - On the wire this looks like: ESC + "PTBL_WTVersion         " + size + data
          (same as _build_data_frame with padded length)
        """
        raw = fname.encode('ascii')
        if len(raw) > 32:
            raise ValueError(f"Version string too long: {len(raw)} > 32")
        # Pad to 16-byte boundary with null bytes
        padded_len = len(raw)
        if padded_len & 0xF:
            padded_len = (padded_len + 16) & 0xFFFFFFF0
        padded_data = raw.ljust(padded_len, b'\x00')
        self.send_data_command("PTBL_WTVersion", padded_data)

    def _send_cwd_data(self, cwd_data: bytes):
        """Send CWD binary data via PTBL_WTCTRLD_UPDATE_CW with fallback.

        SetColorDataWrite (0x180005100) in cspstat64.dll:
        - Tries PTBL_WTCTRLD_UPDATE_CW first
        - Falls back to PTBL_WTCTRLD_UPDATE if first fails
        """
        self.send_data_command("PTBL_WTCTRLD_UPDATE_CW", cwd_data)

    def update_cwd_files(self) -> bool:
        """Step 4: Write all 6 CWD files, then verify final checksums.

        PTBL_RDCWD{dpi}_Checksum is resolution-based, not media-type-based.
        SD and PD share the same resolution slot — the checksum reflects
        whichever was written LAST. Since PD is written after SD, only
        PD checksums can be verified. SD checksums are overwritten by PD.

        Write sequence: SD first (media=1), then PD (media=2).
        Verification: only after ALL 6 files written (final PD checksums).
        """
        cwd_files = [
            # SD (Standard Digital) — written first, checksums overwritten by PD
            ("DS620_SD_300_0111.cwd", "300"),
            ("DS620_SD_600_0111.cwd", "600"),
            ("DS620_SD_610_0111.cwd", "610"),
            # PD (Premium Digital) — written last, final checksums
            ("DS620_PD_300_0111.cwd", "300"),
            ("DS620_PD_600_0111.cwd", "600"),
            ("DS620_PD_610_0111.cwd", "610"),
        ]

        # Expected final checksums (PD, since PD overwrites SD per-resolution)
        # Verified against fleet survey of 30+ working printers
        expected_checksums = {"300": "28B8", "600": "FD23", "610": "547A"}

        # Write all 6 files
        for fname, dpi in cwd_files:
            path = self.cwd_dir / fname
            if not path.exists():
                self.logger.error(f"  CWD file MISSING: {fname}")
                return False

            cwd_data = bytearray(path.read_bytes())

            # Pad to 4-byte boundary with zeros
            pad = len(cwd_data) % 4
            if pad != 0:
                cwd_data += b'\x00' * (4 - pad)

            self.logger.info(f"  Writing {fname} ({len(cwd_data)} bytes)...")

            self._send_cwd_data(bytes(cwd_data))
            time.sleep(3.0)  # Printer needs time to process 37KB before accepting version

            self._send_cwd_version(fname)
            time.sleep(1.0)

        # Verify final checksums (PD values, since PD was written last)
        self.logger.info("  Verifying final CWD checksums...")
        for dpi, expected in expected_checksums.items():
            chk = self.query_command(f"PTBL_RDCWD{dpi}_Checksum 00000000")
            if not chk:
                self.logger.error(f"  No checksum response for CWD{dpi}")
                return False
            chk_s = chk.decode('ascii', errors='replace').strip().strip('\x00').upper()
            if chk_s != expected.upper():
                self.logger.error(f"  CWD{dpi} checksum mismatch: got {chk_s!r}, expected {expected!r}")
                return False
            self.logger.info(f"    CWD{dpi}: checksum {chk_s} OK")

        return True

    def _emergency_reset(self):
        """Attempt to reset printer after a failed update step.

        CRITICAL: Must NOT send PRINTER_RESET while flash is being written
        (FLSHPROG_WRITING = 0x100002). Resetting during a write corrupts
        flash ROM and permanently bricks the device.

        Safe to reset: FLSHPROG_IDLE, FLSHPROG_FINISHED, error states, USUALLY_IDLE
        NOT safe: FLSHPROG_WRITING — must wait for it to finish or error out
        """
        try:
            # Check current state before doing anything destructive.
            # Retry several times — a single CVSTATUS_ERROR could mask FLSHPROG_WRITING
            # if USB is flaky. Sending RESET during WRITING = brick.
            status = CVSTATUS_ERROR
            for _retry in range(5):
                status = self.get_status_code()
                if status != CVSTATUS_ERROR:
                    break
                self.logger.warning(f"  Status read failed, retrying ({_retry+1}/5)...")
                time.sleep(2.0)

            s = status & 0xFFFFFFFF
            self.logger.warning(f"Emergency recovery — printer status: 0x{s:08x}")

            if status == CVSTATUS_ERROR:
                # Cannot determine printer state — USB is dead.
                # DO NOT send reset, printer might be mid-flash-write.
                self.logger.error("=" * 60)
                self.logger.error("CANNOT DETERMINE PRINTER STATE — USB communication failed.")
                self.logger.error("DO NOT power off. Wait for printer LED to stabilize,")
                self.logger.error("then power-cycle.")
                self.logger.error("=" * 60)
                return

            if status == CVS_FLSHPROG_WRITING:
                # NEVER reset during active flash write — wait it out
                self.logger.error("=" * 60)
                self.logger.error("PRINTER IS WRITING FLASH — DO NOT POWER OFF OR DISCONNECT!")
                self.logger.error("Waiting for flash write to complete...")
                self.logger.error("=" * 60)

                safe_to_reset = False
                for i in range(UPDATE_RETRY_COUNT):
                    time.sleep(WAIT_POLL_INTERVAL)
                    status = self.get_status_code()
                    s = status & 0xFFFFFFFF
                    self.logger.info(f"  Flash wait {i+1}: status=0x{s:08x}")

                    if status == CVS_FLSHPROG_WRITING:
                        continue  # Still writing, keep waiting
                    if status in (CVS_USUALLY_IDLE, CVS_USUALLY_PAPER_END, CVS_USUALLY_RIBBON_END):
                        self.logger.info("Flash completed on its own — printer idle")
                        return  # Printer recovered, no reset needed
                    if status == CVS_FLSHPROG_FINISHED:
                        self.logger.info("Flash finished — sending reset")
                        safe_to_reset = True
                        break
                    if status in (CVS_FLSHPROG_DATA_ERR1, CVS_FLSHPROG_DEVICE_ERR1, 0x100020):
                        self.logger.error(f"Flash error 0x{s:08x} — sending reset")
                        safe_to_reset = True
                        break
                    if status == CVSTATUS_ERROR:
                        continue  # Communication error, keep trying
                    # Unknown state — break and try reset
                    safe_to_reset = True
                    break

                if not safe_to_reset:
                    # Loop exhausted with WRITING or CVSTATUS_ERROR — DO NOT RESET
                    self.logger.error("=" * 60)
                    self.logger.error("FLASH WRITE DID NOT COMPLETE — DO NOT POWER OFF!")
                    self.logger.error("Wait for printer LED to stop flashing, then power-cycle.")
                    self.logger.error("=" * 60)
                    return

            self.logger.warning("Sending PRINTER_RESET...")
            self.send_command("PCNTRL PRINTER_RESET")
            time.sleep(5.0)
            self.logger.warning("Reset sent. Power-cycle printer if it doesn't recover.")

        except Exception as e:
            self.logger.error(f"Emergency reset failed: {e}")
            self.logger.error("POWER-CYCLE THE PRINTER to recover.")

    def finalize_update(self):
        """Step 5: Reset printer after CWD update.

        NOTE: PTBL_CL ("SetColorDataClear") ERASES CWD data — do NOT call it
        after writing CWD files. The CWD data written via PTBL_WTCTRLD_UPDATE_CW
        is already persisted. PTBL_CL destroys it.

        The .NET updater calls cwdClear but may use it differently (clear staging
        area before commit). On DS620 04.52, calling PTBL_CL after CWD writes
        resets all checksums to 0000 — confirmed empirically.
        """
        self.logger.info("Finalizing: sending printer reset...")
        self.send_command("PCNTRL PRINTER_RESET")
        time.sleep(2.0)
        self.logger.info("Printer reset sent (LED should return to solid green)")

    def verify_update(self) -> bool:
        """Re-query firmware version after update with retry.

        Extracts expected version from firmware filename (e.g., DS620_0452.s → "0452").
        Retries version read with increasing delays since printer may still be booting.
        Tries both PTBL_RDVersion and PINFO FVER — either matching is success.
        """
        import re
        expected = None
        m = re.search(r'_(\d{2})(\d{2})(?:\D|$)', self.firmware_path.stem)
        if m:
            # Match both "0452" and "04.52" formats in version strings
            expected = f"{m.group(1)}.{m.group(2)}"  # "04.52"
        self.logger.info(f"Verifying firmware version (expected: {expected or 'unknown'})...")

        # Retry with increasing delays — printer may take 5-30s to reinitialize.
        # PRINTER_RESET causes USB re-enumeration, so reconnect on failure.
        reconnected = False
        for wait in (5, 10, 15):
            time.sleep(wait)

            # Try USB reconnect if queries are failing (device re-enumerated)
            if not reconnected:
                r = self.query_command("PSTATUS")
                if r is None:
                    self.logger.info("  USB lost after reset — reconnecting...")
                    time.sleep(3.0)
                    if self._reconnect_usb():
                        reconnected = True
                        self.logger.info("  USB reconnected for verification")

            for cmd, label in [
                ("PTBL_RDVersion         00000000", "PTBL"),
                ("PINFO  FVER", "PINFO"),
            ]:
                r = self.query_command(cmd)
                if not r:
                    continue
                ver = r.decode('ascii', errors='replace').strip().strip('\x00')
                self.logger.info(f"  Firmware version ({label}): {ver}")
                if expected and expected in ver:
                    self.logger.info("Firmware update VERIFIED OK!")
                    return True
                if not expected:
                    # No expected version to compare — any response means printer is alive
                    self.logger.info("Firmware update complete (cannot verify specific version)")
                    return True
                # Mismatch on this command — try next command before giving up
                self.logger.warning(f"  '{expected}' not in '{ver}' via {label}")

            self.logger.debug("  No version match yet, retrying...")

        self.logger.error("Could not verify firmware version after update")
        return False

    # ── CUPS management ──────────────────────────────────────────────────

    def manage_cups(self, action: str = 'stop'):
        if action == 'stop':
            try:
                r = subprocess.run(['systemctl', 'is-active', 'cups'], capture_output=True, text=True, timeout=10)
                if r.stdout.strip() == 'active':
                    self.cups_was_running = True
                    self.logger.info("Stopping CUPS...")
                    subprocess.run(['sudo', 'systemctl', 'stop', 'cups-browsed'], capture_output=True, timeout=30)
                    subprocess.run(['sudo', 'systemctl', 'stop', 'cups'], capture_output=True, check=True, timeout=30)
                    self.logger.info("CUPS stopped")
                    time.sleep(2)
            except Exception as e:
                self.logger.warning(f"Could not stop CUPS: {e}")

    # ── Main entry points ────────────────────────────────────────────────

    def dry_run(self) -> bool:
        """Check printer status and versions without making any changes."""
        self.logger.info("=== DRY RUN — no changes will be made ===")
        try:
            if not self.find_printer():
                return False
            if not self.setup_usb():
                return False

            self.get_device_id()
            self.get_printer_info()
            self.check_cwd_versions()
            self.get_life_counter()

            self.logger.info("\n--- Firmware file ---")
            if self.firmware_path.exists():
                st = self.firmware_path.stat()
                self.logger.info(f"  {self.firmware_path}: {st.st_size} bytes")
                with open(self.firmware_path, 'r', encoding='ascii', errors='replace') as f:
                    lines = f.readlines()
                self.logger.info(f"  S-Record lines: {len(lines)}")
            else:
                self.logger.error(f"  NOT FOUND: {self.firmware_path}")

            self.logger.info("\n--- CWD files ---")
            for fname in ["DS620_PD_300_0111.cwd", "DS620_PD_600_0111.cwd", "DS620_PD_610_0111.cwd",
                           "DS620_SD_300_0111.cwd", "DS620_SD_600_0111.cwd", "DS620_SD_610_0111.cwd"]:
                p = self.cwd_dir / fname
                if p.exists():
                    self.logger.info(f"  OK  {fname} ({p.stat().st_size} bytes)")
                else:
                    self.logger.warning(f"  MISSING  {fname}")

            self.logger.info("\n--- Additional status ---")
            for cmd, label in [
                ("PINFO  SENSOR",         "Sensor"),
                ("PINFO  MEDIA_CLASS_RFID", "Media RFID"),
                ("PMNT_RDUSB_ISERI_SET",  "USB serial setting"),
            ]:
                r = self.query_command(cmd)
                if r:
                    self.logger.info(f"  {label}: {r.decode('ascii', errors='replace').strip()}")

            self.logger.info("\nDry run complete. Run without --dry-run to perform actual update.")
            return True
        except Exception as e:
            self.logger.error(f"Dry run failed: {e}")
            return False
        finally:
            if self.device:
                usb.util.dispose_resources(self.device)

    def run_update(self) -> bool:
        """Execute the full firmware update sequence."""
        try:
            if not self.find_printer():
                return False
            if not self.setup_usb():
                return False

            self.get_device_id()
            self.get_printer_info()
            self.check_cwd_versions()

            # Verify printer is in a normal operational state before starting update.
            # Idle, paper-end, and ribbon-end are all acceptable — firmware flash
            # doesn't use ribbon or paper. Only block on actual errors or busy states.
            ACCEPTABLE_STATES = (CVS_USUALLY_IDLE, CVS_USUALLY_PAPER_END, CVS_USUALLY_RIBBON_END, CVS_FLSHPROG_IDLE)
            status = self.get_status_code()
            if status not in ACCEPTABLE_STATES:
                s = status & 0xFFFFFFFF
                self.logger.error(f"Printer not ready (status=0x{s:08x}). Cannot start update.")
                self.logger.error("Resolve printer errors and retry.")
                return False

            print("\n" + "=" * 60)
            print("WARNING: Firmware update will begin.")
            print("DO NOT disconnect USB or power during the update!")
            print("=" * 60 + "\n")

            if input("Continue? (yes/no): ").strip().lower() != 'yes':
                self.logger.info("Cancelled by user")
                return False

            self.update_in_progress = True
            t0 = time.time()

            # Step 1: Enter flash rewrite mode
            if not self.enter_update_mode():
                self._emergency_reset()
                return False

            # Step 2: Send firmware via PFW_UPDFLASH_PROGRAM
            try:
                if not self.send_firmware():
                    raise RuntimeError("Firmware send returned failure")
            except Exception as fw_err:
                self.logger.error(f"Firmware send failed: {fw_err}")
                # Printer may be in data-receive state after partial transfer.
                # Wait for its internal timeout before sending any commands.
                self.logger.warning("Waiting 30s for printer to timeout on partial data...")
                time.sleep(30)
                self._emergency_reset()
                return False

            # Step 3: Wait for flash programming to complete
            if not self.wait_for_flash():
                self.logger.error("Flash wait failed — attempting printer reset...")
                self._emergency_reset()
                return False

            # Step 4: Update all CWD files
            # Brief delay after flash reboot — let printer fully initialize.
            # .NET updater has implicit delay from UI event processing.
            self.logger.info("Waiting 3s for printer to stabilize after reboot...")
            time.sleep(3.0)

            if not self.update_cwd_files():
                self.logger.error("CWD update failed — resetting printer...")
                # Firmware flash succeeded, so always finalize to clear
                # inconsistent CWD state and reset printer.
                try:
                    self.finalize_update()
                except Exception:
                    pass
                return False

            # Step 5: Finalize and reset
            self.finalize_update()

            self.update_in_progress = False
            elapsed = time.time() - t0

            # Verify
            if self.verify_update():
                self.logger.info(f"Firmware update completed in {elapsed:.0f}s!")
                print("\nIMPORTANT: Reload paper and perform 'Paper Initialization'")
                return True

            self.logger.error("Firmware verification failed")
            return False

        except Exception as e:
            self.logger.error(f"Update failed: {e}")
            if self.update_in_progress:
                self.logger.warning("Update was in progress — attempting emergency reset...")
                time.sleep(10)
                self._emergency_reset()
            return False
        finally:
            self.update_in_progress = False
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(description='DS620A Firmware Updater for Linux')
    parser.add_argument('--firmware', '-f', required=True, help='Path to DS620_0452.s firmware file')
    parser.add_argument('--cwd-dir', '-c', required=True, help='Directory containing CWD files')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug logging')
    parser.add_argument('--dry-run', '-n', action='store_true', help='Check versions without updating')
    parser.add_argument('--log-file', '-l', help='Log output to file')
    parser.add_argument('--no-cups', action='store_true', help='Do not auto-manage CUPS')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    firmware_path = Path(args.firmware)
    cwd_dir = Path(args.cwd_dir)

    if not firmware_path.exists():
        print(f"Error: Firmware file not found: {firmware_path}")
        sys.exit(1)
    if not cwd_dir.is_dir():
        print(f"Error: CWD directory not found: {cwd_dir}")
        sys.exit(1)

    log_file = None
    if args.log_file:
        log_file = f"{args.log_file}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    updater = DS620Updater(str(firmware_path), str(cwd_dir), log_file)

    if not args.dry_run and os.geteuid() != 0:
        print("WARNING: Not running as root — may encounter permission errors.")
        print("Consider: sudo ...\n")

    if args.dry_run:
        ok = updater.dry_run()
    else:
        if not args.no_cups:
            updater.manage_cups('stop')
        ok = updater.run_update()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
