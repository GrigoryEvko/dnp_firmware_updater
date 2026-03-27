#!/usr/bin/env python3
"""
DS620A Firmware Updater for Linux
Protocol reverse-engineered from cspstat64.dll and CSJCX2lm.dll via IDA Pro decompilation.

Wire format (from cspstat64.dll sprintf_s calls):
  - All command frames are exactly 32 bytes: ESC (0x1B) + 31 ASCII chars, space-padded
  - Query response: 8-byte ASCII decimal length + N bytes data
  - Data write: 32-byte header (ESC + cmd[23] + size[8]) + payload + 4-byte LE size trailer
  - NO CRLF termination on commands

USB access: bulk OUT + bulk IN endpoints on printer class interface.
"""

import sys
import os
import time
import struct
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
UPDATE_RETRY_COUNT = 90  # Max retries waiting for flash complete (90 × 2s = 3min)

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
    return bytes([ESC]) + cmd_text.encode('ascii').ljust(FULL_CMD_SIZE)


def _build_data_frame(cmd_text: str, data_len: int) -> bytes:
    """Build 32-byte header for data write commands.

    Format: ESC + cmd_text[23 chars, space-padded] + 8-digit ASCII size = 32 bytes.
    Followed by: payload bytes + 4-byte LE integer size trailer.
    Used for: PFW_UPDFLASH_PROGRAM, PTBL_WTCTRLD_UPDATE_CW, PTBL_WTVersion, etc.
    """
    cmd_part = cmd_text.encode('ascii').ljust(CMD_FIELD_SIZE)
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
        self.logger.setLevel(logging.DEBUG if log_file else logging.INFO)

        console = logging.StreamHandler()
        console.setLevel(logging.getLogger().level)
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
        if self.cups_was_running:
            self.logger.info("Restarting CUPS service...")
            try:
                subprocess.run(['sudo', 'systemctl', 'start', 'cups'],
                               capture_output=True, check=True)
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
            r = subprocess.run(['systemctl', 'is-active', 'cups'], capture_output=True, text=True)
            cups_running = r.stdout.strip() == 'active'
            if cups_running:
                r = subprocess.run(['lpstat', '-v'], capture_output=True, text=True)
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

    def _drain_input(self):
        """Drain any stale data from the IN endpoint."""
        try:
            while True:
                self.ep_in.read(1024, timeout=100)
        except usb.core.USBTimeoutError:
            pass

    # ── Wire protocol primitives ─────────────────────────────────────────
    # Based on cspstat64.dll: sub_180017620 (query), sub_180017870 (write)

    def send_command(self, cmd_text: str):
        """Send a 32-byte command frame (no data, no response expected).

        Used for: PFW_UPDFLASH_REWRITE, PCNTRL PRINTER_RESET, etc.
        """
        frame = _build_frame(cmd_text)
        assert len(frame) == FRAME_SIZE, f"Frame size {len(frame)} != {FRAME_SIZE}"
        self.logger.debug(f"CMD> {cmd_text!r}  [{frame.hex()}]")
        self.ep_out.write(frame)

    def query_command(self, cmd_text: str, timeout: int = TIMEOUT_DEFAULT) -> bytes:
        """Send 32-byte command, read 8-byte ASCII length + data response.

        Protocol (cspstat64.dll sub_180017620):
          Host -> Printer: [32-byte frame]
          Printer -> Host: [8-byte ASCII length][N bytes data]
        """
        frame = _build_frame(cmd_text)
        assert len(frame) == FRAME_SIZE
        self.logger.debug(f"QRY> {cmd_text!r}")
        self.ep_out.write(frame)

        try:
            # Read 8-byte ASCII length prefix
            raw_len = bytes(self.ep_in.read(SIZE_FIELD_LEN, timeout=timeout))
            length = int(raw_len.decode('ascii').strip())
            self.logger.debug(f"  response length: {length} (raw: {raw_len!r})")

            if length <= 0:
                return b''

            # Read exactly N bytes of response data
            data = bytes(self.ep_in.read(length, timeout=timeout))
            self.logger.debug(f"  response data: {data!r}")
            return data

        except usb.core.USBTimeoutError:
            self.logger.debug(f"  timeout (no response)")
            return None
        except (ValueError, UnicodeDecodeError) as e:
            self.logger.debug(f"  parse error: {e}")
            return None

    def send_data_command(self, cmd_text: str, data: bytes, timeout: int = TIMEOUT_UPDATE):
        """Send command with payload: [32-byte header][data chunks][4-byte LE size trailer].

        Protocol (cspstat64.dll sub_180017870 / SetFirmwDataWrite):
          Block 0: ESC + cmd_text[23 chars] + 8-digit ASCII size = 32 bytes
          Block 1: payload data (chunked at 1MB)
          Block 2: 4-byte little-endian integer size
        """
        header = _build_data_frame(cmd_text, len(data))
        assert len(header) == FRAME_SIZE, f"Data header size {len(header)} != {FRAME_SIZE}"
        trailer = struct.pack('<I', len(data))

        self.logger.debug(f"DAT> {cmd_text!r}  size={len(data)}  [{header.hex()}]")

        # Send 32-byte header
        self.ep_out.write(header)

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

        # Send 4-byte LE size trailer (cspstat64.dll Block 3)
        self.ep_out.write(trailer)

        elapsed = time.time() - t0
        self.logger.info(f"  Sent {len(data)} bytes in {elapsed:.1f}s ({len(data) / elapsed / 1024:.0f} KB/s)")

        # Read optional response
        try:
            resp_len = bytes(self.ep_in.read(SIZE_FIELD_LEN, timeout=timeout))
            length = int(resp_len.decode('ascii').strip())
            if length > 0:
                resp = bytes(self.ep_in.read(length, timeout=timeout))
                self.logger.debug(f"  response: {resp!r}")
                return resp
            return b''
        except (usb.core.USBTimeoutError, ValueError):
            return None

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
        """Query PSTATUS and parse the integer status code.

        CvGetStatus in cspstat64.dll returns parsed integer from status response.
        Status codes: CVS_USUALLY_IDLE=0x10001, CVS_FLSHPROG_IDLE=0x100001, etc.
        Returns CVSTATUS_ERROR (-0x80000000) on failure.
        """
        r = self.query_command("PSTATUS")
        if r:
            try:
                # Status response is an integer formatted as string
                status_str = r.decode('ascii', errors='replace').strip()
                # Try parsing as decimal or hex
                if status_str.startswith('0x') or status_str.startswith('0X'):
                    return int(status_str, 16)
                return int(status_str)
            except ValueError:
                self.logger.debug(f"  Could not parse status: {r!r}")
                return CVSTATUS_ERROR
        return CVSTATUS_ERROR

    def enter_update_mode(self) -> bool:
        """Step 1: PFW_UPDFLASH_REWRITE — put printer in flash rewrite mode.

        From Form1.PRINTER_FW (line 3055):
          CvSetFirmwUpdateMode(port)  → sends PFW_UPDFLASH_REWRITE
          SleepDoEvent(4000)          → wait 4 seconds
          Loop CvGetStatus(port) until == CVS_FLSHPROG_IDLE (0x100001)
          Retry up to 30 times with 1s sleep between attempts.
        """
        self.logger.info("Entering firmware update mode (FLASH_REWRITE)...")
        self.send_command("PFW_UPDFLASH_REWRITE")

        self.logger.info(f"  Waiting {WAIT_CHMODE}s for mode change...")
        time.sleep(WAIT_CHMODE)

        # Poll status until CVS_FLSHPROG_IDLE
        for attempt in range(MODE_RETRY_COUNT):
            time.sleep(1.0)
            status = self.get_status_code()
            self.logger.debug(f"  Status poll {attempt + 1}/{MODE_RETRY_COUNT}: 0x{status & 0xFFFFFFFF:08x}")

            if status == CVS_FLSHPROG_IDLE:
                self.logger.info("Printer in flash program mode (FLSHPROG_IDLE)")
                return True
            if status == CVSTATUS_ERROR:
                # cspstat64.dll returns CVSTATUS_ERROR for communication failures
                # Keep retrying as per .NET updater logic
                continue

        self.logger.error(f"Failed to enter update mode after {MODE_RETRY_COUNT} attempts")
        return False

    def send_firmware(self) -> bool:
        """Step 2: PFW_UPDFLASH_PROGRAM — send S-Record firmware data.

        From Form1.PRINTER_FW (line 3082):
          SetFirmwDataWrite(port, array, num)
          → cspstat64.dll sends PFW_UPDFLASH_PROGRAM + 8-digit size + data + 4-byte LE size

        Firmware data is padded to 32-byte boundary with zeros (Form1 line 3041-3049).
        """
        self.logger.info(f"Sending firmware: {self.firmware_path}")

        with open(self.firmware_path, 'rb') as f:
            firmware = f.read()

        # Pad to 32-byte boundary with zeros (from Form1.PRINTER_FW line 3041)
        pad = len(firmware) % 32
        if pad != 0:
            firmware += b'\x00' * pad
            self.logger.debug(f"  Padded {pad} bytes to 32-byte boundary")

        self.logger.info(f"  Size: {len(firmware)} bytes ({len(firmware) / 1024 / 1024:.1f} MB)")

        self.send_data_command("PFW_UPDFLASH_PROGRAM", firmware, timeout=TIMEOUT_FLASH)
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

        self.logger.error(f"Flash timed out after {UPDATE_RETRY_COUNT * WAIT_POLL_INTERVAL:.0f}s")
        return False

    def update_cwd_files(self) -> bool:
        """Step 4: Update each CWD file — version first, then binary data, then verify.

        From Module1.PRINTER_TBLW_ALL (line 96-170):
          1. SetColorDataVersion(port, filename, len)  → PTBL_WTVersion + filename
          2. SetColorDataWrite(port, cwd_bytes, len)    → PTBL_WTCTRLD_UPDATE_CW + data
          3. GetCwdVersion(dpi, media) to verify         → PTBL_RDCWD{dpi}_Version
          4. GetCwdCheckSum(dpi, media) to verify         → PTBL_RDCWD{dpi}_Checksum

        CWD data padded to 4-byte boundary (Module1 line 123-134).
        Order from Form1.cwdUpdate: SD first (media=1), then PD (media=2).
        """
        # (filename, expected_checksum, dpi_for_verify)
        cwd_sequence = [
            # SD (Standard Digital) — media=1
            ("DS620_SD_300_0111.cwd", "28B7", "300"),
            ("DS620_SD_600_0111.cwd", "FD22", "600"),
            ("DS620_SD_610_0111.cwd", "5479", "610"),
            # PD (Premium Digital) — media=2
            ("DS620_PD_300_0111.cwd", "28B8", "300"),
            ("DS620_PD_600_0111.cwd", "FD23", "600"),
            ("DS620_PD_610_0111.cwd", "547A", "610"),
        ]

        for fname, expected_csum, dpi in cwd_sequence:
            path = self.cwd_dir / fname
            if not path.exists():
                self.logger.error(f"  CWD file MISSING: {fname}")
                return False

            cwd_data = bytearray(path.read_bytes())

            # Pad to 4-byte boundary with zeros (Module1.PRINTER_TBLW_ALL line 123-134)
            pad = len(cwd_data) % 4
            if pad != 0:
                cwd_data += b'\x00' * (4 - pad)

            self.logger.info(f"  Updating {fname} ({len(cwd_data)} bytes)...")

            # Step 1: Set version (filename is the version string)
            self.send_data_command("PTBL_WTVersion", fname.encode('ascii'))

            # Step 2: Write CWD binary data
            self.send_data_command("PTBL_WTCTRLD_UPDATE_CW", bytes(cwd_data))
            time.sleep(1.0)

            # Step 3: Verify version
            ver = self.query_command(f"PTBL_RDCWD{dpi}_Version  00000000")
            if ver:
                ver_s = ver.decode('ascii', errors='replace').strip().upper()
                if ver_s != fname.upper():
                    self.logger.error(f"  Version mismatch: got {ver_s!r}, expected {fname.upper()!r}")
                    return False
                self.logger.info(f"    Version verified: {ver_s}")

            # Step 4: Verify checksum
            chk = self.query_command(f"PTBL_RDCWD{dpi}_Checksum 00000000")
            if chk:
                chk_s = chk.decode('ascii', errors='replace').strip().upper()
                if chk_s != expected_csum.upper():
                    self.logger.error(f"  Checksum mismatch: got {chk_s!r}, expected {expected_csum!r}")
                    return False
                self.logger.info(f"    Checksum verified: {chk_s}")

        return True

    def finalize_update(self):
        """Step 5: Clear CWD tables and reset printer.

        From Form1.cwdClear (line 2944): SetColorDataClear → PTBL_CL
        Then PCNTRL PRINTER_RESET to reboot.
        """
        self.logger.info("Finalizing: clear CWD tables + reset...")
        self.send_command("PTBL_CL                00000000")
        time.sleep(0.5)
        self.send_command("PCNTRL PRINTER_RESET")
        time.sleep(2.0)
        self.logger.info("Printer reset sent (LED should return to solid green)")

    def verify_update(self) -> bool:
        """Re-query firmware version after update."""
        self.logger.info("Verifying firmware version...")
        time.sleep(5.0)  # Wait for printer to fully restart

        r = self.query_command("PTBL_RDVersion         00000000")
        if r:
            ver = r.decode('ascii', errors='replace').strip()
            self.logger.info(f"  New firmware version: {ver}")
            if "04.52" in ver or "0452" in ver:
                self.logger.info("Firmware update VERIFIED OK!")
                return True
            self.logger.warning(f"  Version doesn't match expected 04.52")
            return False

        r = self.query_command("PINFO  FVER")
        if r:
            ver = r.decode('ascii', errors='replace').strip()
            self.logger.info(f"  Firmware (PINFO): {ver}")
            return "04.52" in ver or "0452" in ver

        self.logger.error("Could not read firmware version after update")
        return False

    # ── CUPS management ──────────────────────────────────────────────────

    def manage_cups(self, action: str = 'stop'):
        if action == 'stop':
            try:
                r = subprocess.run(['systemctl', 'is-active', 'cups'], capture_output=True, text=True)
                if r.stdout.strip() == 'active':
                    self.cups_was_running = True
                    self.logger.info("Stopping CUPS...")
                    subprocess.run(['sudo', 'systemctl', 'stop', 'cups-browsed'], capture_output=True)
                    subprocess.run(['sudo', 'systemctl', 'stop', 'cups'], capture_output=True, check=True)
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
                with open(self.firmware_path) as f:
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
            self.manage_cups('stop')

            if not self.find_printer():
                return False
            if not self.setup_usb():
                return False

            self.get_device_id()
            self.get_printer_info()
            self.check_cwd_versions()

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
                return False

            # Step 2: Send firmware via PFW_UPDFLASH_PROGRAM
            if not self.send_firmware():
                return False

            # Step 3: Wait for flash programming to complete
            if not self.wait_for_flash():
                return False

            # Step 4: Clear old CWD and update all CWD files
            # From Form1.btnStart_Click: cwdClear() then cwdUpdate()
            self.send_command("PTBL_CL                00000000")  # cwdClear
            time.sleep(0.5)

            if not self.update_cwd_files():
                self.logger.error("CWD update failed")
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
            self.update_in_progress = False
            return False
        finally:
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
        if args.no_cups:
            updater.cups_was_running = False
        ok = updater.run_update()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
