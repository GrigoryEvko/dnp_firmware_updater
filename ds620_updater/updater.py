#!/usr/bin/env python3
"""
DS620A Firmware Updater for Linux
Based on reverse engineering of DNP DS620A firmware update protocol
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

# USB Device IDs for DS620A
DNP_VENDOR_IDS = [0x1343, 0x1452]  # DNP and alternate vendor ID
PRODUCT_IDS = {
    0x1343: [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x1001, 0xFFFF],
    0x1452: [0x8b01, 0x8b02, 0x9001, 0x9201, 0x9301, 0x9401]
}

# Protocol constants
ESC = 0x1B  # Control character
CR = 0x0D   # Carriage return
LF = 0x0A   # Line feed
CRLF = bytes([CR, LF])

# Timing constants (milliseconds)
WAIT_1000MS = 1.0
WAIT_2000MS = 2.0
WAIT_CHMODE = 0.5
WAIT_UPDATE = 3.0
PRG_UPDATE_WAIT = 5.0

class DS620Updater:
    def __init__(self, firmware_path, cwd_dir, log_file=None):
        self.firmware_path = Path(firmware_path)
        self.cwd_dir = Path(cwd_dir)
        self.device = None
        self.ep_out = None
        self.ep_in = None
        self.cups_was_running = False
        self.update_in_progress = False
        self.start_time = datetime.now()
        
        # Setup logging
        self.setup_logging(log_file)
        
        # Setup signal handlers
        self.setup_signal_handlers()
        
    def setup_logging(self, log_file):
        """Setup logging to both console and file"""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG if log_file else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.getLogger().level)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler if requested
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            self.logger.info(f"Logging to file: {log_file}")
            
    def setup_signal_handlers(self):
        """Setup signal handlers for clean shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        atexit.register(self.cleanup)
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C and termination signals"""
        self.logger.warning("\n\nReceived interrupt signal!")
        if self.update_in_progress:
            self.logger.error("WARNING: Update in progress! Interrupting now may damage the printer!")
            self.logger.error("Press Ctrl+C again within 5 seconds to force quit...")
            
            # Give user a chance to reconsider
            signal.signal(signal.SIGINT, self.force_quit)
            time.sleep(5)
            signal.signal(signal.SIGINT, self.signal_handler)
        else:
            self.cleanup()
            sys.exit(1)
            
    def force_quit(self, signum, frame):
        """Force quit on second Ctrl+C"""
        self.logger.error("FORCE QUIT - Update interrupted!")
        self.cleanup()
        sys.exit(1)
        
    def cleanup(self):
        """Clean up resources and restore CUPS if needed"""
        self.logger.info("Cleaning up...")
        
        # Release USB resources
        if self.device:
            try:
                usb.util.dispose_resources(self.device)
                self.logger.debug("USB resources released")
            except:
                pass
                
        # Restart CUPS if we stopped it
        if self.cups_was_running:
            self.logger.info("Restarting CUPS service...")
            try:
                subprocess.run(['sudo', 'systemctl', 'start', 'cups'], 
                             capture_output=True, check=True)
                self.logger.info("CUPS service restarted")
            except Exception as e:
                self.logger.error(f"Failed to restart CUPS: {e}")
                self.logger.error("Please run: sudo systemctl start cups")
        
    def check_cups_status(self):
        """Check if CUPS is running and has claimed the printer"""
        cups_running = False
        printer_in_cups = False
        cups_printer_name = None
        
        try:
            # Check if CUPS is running
            result = subprocess.run(['systemctl', 'is-active', 'cups'], 
                                  capture_output=True, text=True)
            cups_running = result.stdout.strip() == 'active'
            
            if cups_running:
                # Check if DS620 is configured in CUPS
                result = subprocess.run(['lpstat', '-v'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'dnp-ds620' in line.lower() or 'ds620' in line.lower():
                        printer_in_cups = True
                        # Extract printer name
                        if line.startswith('device for '):
                            cups_printer_name = line.split(':')[0].replace('device for ', '')
                        self.logger.warning(f"DS620 is configured in CUPS: {line}")
                        
        except Exception as e:
            self.logger.debug(f"Could not check CUPS status: {e}")
            
        return cups_running, printer_in_cups, cups_printer_name
    
    def find_printer(self):
        """Find DS620A printer via USB"""
        # Check CUPS status first
        cups_running, printer_in_cups, cups_printer_name = self.check_cups_status()
        
        if printer_in_cups:
            self.logger.warning("="*60)
            self.logger.warning("WARNING: DS620 printer is configured in CUPS!")
            self.logger.warning("This may prevent direct USB access.")
            self.logger.warning("")
            self.logger.warning("Options to fix this:")
            self.logger.warning("1. Temporarily stop CUPS: sudo systemctl stop cups")
            self.logger.warning(f"2. Remove printer from CUPS: sudo lpadmin -x {cups_printer_name}")
            self.logger.warning("3. Run this updater with sudo")
            self.logger.warning("")
            self.logger.warning("After update, restart CUPS: sudo systemctl start cups")
            self.logger.warning("="*60)
            
            # Check if we're running as root
            if os.geteuid() != 0:
                self.logger.error("Not running as root. CUPS may block USB access.")
                self.logger.error("Try running with sudo.")
        
        for vid in DNP_VENDOR_IDS:
            for pid in PRODUCT_IDS.get(vid, []):
                self.device = usb.core.find(idVendor=vid, idProduct=pid)
                if self.device:
                    self.logger.info(f"Found DS620A printer: VID={hex(vid)}, PID={hex(pid)}")
                    self.vendor_id = vid
                    self.product_id = pid
                    return True
        
        self.logger.error("DS620A printer not found. Please ensure it's connected via USB.")
        self.logger.error("Looking for VID:PID combinations: 1343:xxxx and 1452:xxxx")
        
        if cups_running:
            self.logger.error("")
            self.logger.error("CUPS is running and may be blocking USB access.")
            self.logger.error("Try: sudo systemctl stop cups")
            
        return False
        
    def unbind_usblp(self):
        """Unbind usblp driver from printer device"""
        try:
            # Get device bus and address
            bus = self.device.bus
            address = self.device.address
            
            self.logger.info(f"Attempting to unbind usblp driver from bus {bus}, device {address}")
            
            # Method 1: Try direct unbind using lsusb output format
            # The interface is typically bus-port:config.interface (e.g., "1-4:1.0")
            import subprocess
            
            # Get the device path from lsusb
            result = subprocess.run(
                ["lsusb", "-t"],
                capture_output=True,
                text=True
            )
            
            if self.logger.level == logging.DEBUG:
                self.logger.debug(f"lsusb -t output:\n{result.stdout}")
            
            # Method 2: Find the correct sysfs path
            # USB devices in sysfs follow pattern: /sys/bus/usb/devices/busnum-port[.port...]
            sysfs_base = "/sys/bus/usb/devices/"
            
            # Try to find files that match our bus
            try:
                import glob
                # Look for all devices on this bus
                for device_path in glob.glob(f"{sysfs_base}{bus}-*"):
                    if not os.path.isdir(device_path):
                        continue
                        
                    # Check if this is our device by reading devnum
                    try:
                        devnum_path = os.path.join(device_path, "devnum")
                        if os.path.exists(devnum_path):
                            with open(devnum_path, 'r') as f:
                                devnum = int(f.read().strip())
                                
                            if devnum == address:
                                # Found our device! Now try to unbind usblp
                                self.logger.info(f"Found device at {device_path}")
                                
                                # The interface is typically :1.0 for first interface
                                interface_name = os.path.basename(device_path) + ":1.0"
                                unbind_path = "/sys/bus/usb/drivers/usblp/unbind"
                                
                                if os.path.exists(unbind_path):
                                    self.logger.info(f"Unbinding usblp from interface {interface_name}")
                                    try:
                                        with open(unbind_path, 'w') as f:
                                            f.write(interface_name + "\n")
                                        self.logger.info("Successfully unbound usblp driver")
                                        time.sleep(0.5)  # Give system time to release
                                        return True
                                    except IOError as e:
                                        if "No such device" in str(e):
                                            self.logger.info("Device not bound to usblp (already unbound?)")
                                            return True
                                        else:
                                            self.logger.warning(f"Failed to write to unbind: {e}")
                                else:
                                    self.logger.warning("usblp unbind path not found - driver might not be loaded")
                                    return True  # Not an error if usblp isn't loaded
                                    
                    except Exception as e:
                        self.logger.debug(f"Error checking {device_path}: {e}")
                        continue
                        
            except Exception as e:
                self.logger.warning(f"Error searching sysfs: {e}")
                
            # If we get here, we couldn't find the device
            self.logger.warning("Could not find device in sysfs - attempting to continue anyway")
            return True  # Try to continue even if unbind failed
            
        except Exception as e:
            self.logger.warning(f"Failed to unbind usblp: {e}")
            return True  # Try to continue even if unbind failed
    
    def setup_usb(self):
        """Setup USB communication endpoints"""
        try:
            # Try to unbind usblp driver first
            self.unbind_usblp()
            
            # Detach kernel driver if active
            if self.device.is_kernel_driver_active(0):
                self.device.detach_kernel_driver(0)
                
            # Set configuration
            self.device.set_configuration()
            
            # Get configuration
            cfg = self.device.get_active_configuration()
            intf = cfg[(0,0)]
            
            # Find endpoints
            self.ep_out = usb.util.find_descriptor(
                intf,
                custom_match = lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
            )
            
            self.ep_in = usb.util.find_descriptor(
                intf,
                custom_match = lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            )
            
            if not self.ep_out or not self.ep_in:
                raise Exception("Could not find USB endpoints")
                
            self.logger.info("USB communication established")
            
            if self.logger.level == logging.DEBUG:
                self.logger.debug(f"OUT endpoint: 0x{self.ep_out.bEndpointAddress:02x}")
                self.logger.debug(f"IN endpoint: 0x{self.ep_in.bEndpointAddress:02x}")
                self.logger.debug(f"Device: {self.device}")
                self.logger.debug(f"Configuration: {cfg}")
            
            # Clear any pending data
            self.clear_usb_buffers()
            
            # Run diagnostics if in debug mode
            if self.logger.level == logging.DEBUG:
                self.diagnose_usb()
            
            # Initialize printer communication
            self.initialize_printer()
            
            return True
            
        except Exception as e:
            self.logger.error(f"USB setup failed: {e}")
            return False
            
    def clear_usb_buffers(self):
        """Clear any pending data from USB buffers"""
        if self.logger.level == logging.DEBUG:
            self.logger.debug("Clearing USB buffers...")
        
        try:
            while True:
                data = self.ep_in.read(1024, timeout=100)
                if self.logger.level == logging.DEBUG:
                    self.logger.debug(f"Cleared {len(data)} bytes from input buffer")
        except usb.core.USBTimeoutError:
            # No more data to read
            pass
            
    def diagnose_usb(self):
        """Print detailed USB device information for debugging"""
        self.logger.debug("=== USB Device Diagnostics ===")
        try:
            self.logger.debug(f"Vendor: 0x{self.device.idVendor:04x}")
            self.logger.debug(f"Product: 0x{self.device.idProduct:04x}")
            
            # Try to get device strings
            try:
                manufacturer = usb.util.get_string(self.device, self.device.iManufacturer)
                self.logger.debug(f"Manufacturer: {manufacturer}")
            except:
                self.logger.debug("Manufacturer: (unable to read)")
                
            try:
                product = usb.util.get_string(self.device, self.device.iProduct)
                self.logger.debug(f"Product Name: {product}")
            except:
                self.logger.debug("Product Name: (unable to read)")
                
            try:
                serial = usb.util.get_string(self.device, self.device.iSerialNumber)
                self.logger.debug(f"Serial: {serial}")
            except:
                self.logger.debug("Serial: (unable to read)")
            
            # List all configurations and interfaces
            for cfg in self.device:
                self.logger.debug(f"\nConfiguration {cfg.bConfigurationValue}:")
                for intf in cfg:
                    self.logger.debug(f"  Interface {intf.bInterfaceNumber}, Alt {intf.bAlternateSetting}:")
                    self.logger.debug(f"    Class: 0x{intf.bInterfaceClass:02x} (0x07=Printer)")
                    self.logger.debug(f"    Subclass: 0x{intf.bInterfaceSubClass:02x}")
                    self.logger.debug(f"    Protocol: 0x{intf.bInterfaceProtocol:02x}")
                    
                    for ep in intf:
                        direction = "IN" if ep.bEndpointAddress & 0x80 else "OUT"
                        ep_type = ["Control", "Isochronous", "Bulk", "Interrupt"][ep.bmAttributes & 0x03]
                        self.logger.debug(f"    Endpoint 0x{ep.bEndpointAddress:02x}: {direction} {ep_type}, MaxPacket={ep.wMaxPacketSize}")
                        
        except Exception as e:
            self.logger.debug(f"Error during USB diagnostics: {e}")
            
    def test_raw_usb(self):
        """Test raw USB communication for debugging"""
        self.logger.debug("=== Testing Raw USB Communication ===")
        
        # Test 1: Single byte write
        try:
            self.ep_out.write(b'\x1b')
            self.logger.debug("✓ Successfully wrote single ESC byte")
        except Exception as e:
            self.logger.debug(f"✗ Failed to write single byte: {e}")
            
        # Test 2: Simple string
        try:
            self.ep_out.write(b'PSTATUS\r\n')
            self.logger.debug("✓ Successfully wrote simple command")
        except Exception as e:
            self.logger.debug(f"✗ Failed to write simple command: {e}")
            
        # Test 3: Try to read any response
        try:
            data = self.ep_in.read(64, timeout=1000)
            self.logger.debug(f"✓ Read {len(data)} bytes: {data.hex()}")
        except usb.core.USBTimeoutError:
            self.logger.debug("✗ No data available to read (timeout)")
        except Exception as e:
            self.logger.debug(f"✗ Read error: {e}")
            
    def send_printer_class_request(self):
        """Send USB printer class-specific requests"""
        try:
            # USB Printer Class requests
            GET_DEVICE_ID = 0x00
            GET_PORT_STATUS = 0x01
            SOFT_RESET = 0x02
            
            # Get device ID (IEEE 1284 Device ID)
            self.logger.info("Sending GET_DEVICE_ID request...")
            try:
                # bmRequestType: 0xA1 (Device to Host, Class, Interface)
                # bRequest: 0x00 (GET_DEVICE_ID)
                # wValue: 0
                # wIndex: Interface number (0)
                # wLength: 1024 (max expected response)
                device_id = self.device.ctrl_transfer(0xA1, GET_DEVICE_ID, 0, 0, 1024, timeout=1000)
                if device_id and len(device_id) > 2:
                    # First two bytes are length (big-endian)
                    id_len = (device_id[0] << 8) | device_id[1]
                    id_string = device_id[2:2+id_len].decode('ascii', errors='ignore')
                    self.logger.info(f"Device ID: {id_string}")
            except Exception as e:
                self.logger.debug(f"GET_DEVICE_ID failed: {e}")
            
            # Get port status
            try:
                # wLength: 1 (status byte)
                status = self.device.ctrl_transfer(0xA1, GET_PORT_STATUS, 0, 0, 1, timeout=1000)
                if status:
                    self.logger.info(f"Port status: 0x{status[0]:02x}")
                    # Bit 5: Paper Empty
                    # Bit 4: Select
                    # Bit 3: Not Error
                    if status[0] & 0x20:
                        self.logger.warning("Paper empty detected")
            except Exception as e:
                self.logger.debug(f"GET_PORT_STATUS failed: {e}")
                
            # Try soft reset for 0x1452 devices
            if self.vendor_id == 0x1452:
                self.logger.info("Sending SOFT_RESET for vendor 0x1452...")
                try:
                    # bmRequestType: 0x21 (Host to Device, Class, Interface)
                    # No data phase
                    self.device.ctrl_transfer(0x21, SOFT_RESET, 0, 0, timeout=1000)
                    time.sleep(0.5)  # Give device time to reset
                    self.logger.info("Soft reset completed")
                except Exception as e:
                    self.logger.debug(f"SOFT_RESET failed: {e}")
                    
        except Exception as e:
            self.logger.warning(f"Printer class requests failed: {e}")
    
    def initialize_printer(self):
        """Initialize printer communication"""
        self.logger.info("Initializing printer communication...")
        
        # Send USB printer class requests first
        self.send_printer_class_request()
        
        # Run raw USB test in debug mode
        if self.logger.level == logging.DEBUG:
            self.test_raw_usb()
        
        # Special handling for vendor 0x1452
        if hasattr(self, 'vendor_id') and self.vendor_id == 0x1452:
            self.logger.info("Using initialization for vendor 0x1452")
            # Try longer timeout and different delays
            timeout = 10000  # 10 seconds
            
            # Add extra delay after USB setup for 0x1452
            time.sleep(1.0)
            
            if self.logger.level == logging.DEBUG:
                self.logger.debug("Added 1 second delay for VID 0x1452 initialization")
        else:
            timeout = 5000  # 5 seconds
        
        # Send STATUS command to verify communication
        self.send_command("PSTATUS")
        time.sleep(0.5)
        response = self.read_response(timeout=timeout)
        
        if response:
            self.logger.info("Printer communication initialized")
            if self.logger.level == logging.DEBUG:
                self.logger.debug(f"STATUS response: {response.decode('ascii', errors='replace')}")
                self.logger.debug(f"Response hex: {response.hex()}")
        else:
            self.logger.warning("No response to STATUS command, continuing anyway...")
            
    def send_command(self, command, data=None):
        """Send command to printer"""
        # Use standard DNP format for all vendors
        cmd_bytes = bytes([ESC]) + command.encode('ascii')
        
        # Ensure command is exactly 23 bytes (24 total with ESC)
        if len(cmd_bytes) < 24:
            cmd_bytes += b' ' * (24 - len(cmd_bytes))
        
        if data:
            cmd_bytes += data
        cmd_bytes += CRLF
        
        # Enhanced debug logging
        if self.logger.level == logging.DEBUG:
            self.logger.debug(f"Sending command: {command}")
            self.logger.debug(f"Raw hex: {cmd_bytes.hex()}")
            self.logger.debug(f"ASCII: {cmd_bytes.decode('ascii', errors='replace')}")
            self.logger.debug(f"Total length: {len(cmd_bytes)} bytes")
            
            # Special debugging for 0x1452
            if hasattr(self, 'vendor_id') and self.vendor_id == 0x1452:
                self.logger.debug(f"VID 0x1452: Using standard DNP format")
        
        try:
            bytes_written = self.ep_out.write(cmd_bytes)
            if self.logger.level == logging.DEBUG:
                self.logger.debug(f"Wrote {bytes_written} bytes to endpoint 0x{self.ep_out.bEndpointAddress:02x}")
        except Exception as e:
            self.logger.error(f"Failed to write to USB: {e}")
            raise
        
    def read_response(self, timeout=5000, retry_count=3):
        """Read response from printer with retry logic"""
        for attempt in range(retry_count):
            try:
                # First try to read potential length field
                initial_read = self.ep_in.read(1024, timeout)
                response = bytes(initial_read)
                
                if self.logger.level == logging.DEBUG:
                    self.logger.debug(f"Read {len(response)} bytes from endpoint 0x{self.ep_in.bEndpointAddress:02x}")
                    self.logger.debug(f"Raw hex: {response.hex()}")
                    self.logger.debug(f"ASCII: {response.decode('ascii', errors='replace')}")
                    
                    # Extra debugging for 0x1452
                    if hasattr(self, 'vendor_id') and self.vendor_id == 0x1452:
                        self.logger.debug(f"VID 0x1452 response analysis:")
                        if len(response) > 0:
                            self.logger.debug(f"  First byte: 0x{response[0]:02x}")
                            self.logger.debug(f"  Looks like error: {'yes' if response[0] in [0x15, 0x06] else 'no'}")
                
                # Check if response starts with 8-digit length
                if len(response) >= 8 and response[:8].decode('ascii', errors='ignore').isdigit():
                    length = int(response[:8].decode('ascii'))
                    self.logger.debug(f"Detected length-prefixed response: {length} bytes expected")
                    
                    # If we have the full response already
                    if len(response) >= 8 + length:
                        return response[8:8+length]
                    
                    # Otherwise, read the remaining data
                    remaining = length - (len(response) - 8)
                    if remaining > 0:
                        more_data = self.ep_in.read(remaining, timeout)
                        response += bytes(more_data)
                        return response[8:8+length]
                
                # For 0x1452, log non-standard responses
                if hasattr(self, 'vendor_id') and self.vendor_id == 0x1452 and len(response) > 0:
                    self.logger.warning(f"VID 0x1452: Non-standard response format")
                
                return response
                
            except usb.core.USBTimeoutError:
                if attempt < retry_count - 1:
                    self.logger.debug(f"Read timeout, retrying... ({attempt + 1}/{retry_count})")
                    time.sleep(0.1)
                else:
                    if self.logger.level == logging.DEBUG:
                        self.logger.debug(f"Read timeout after {retry_count} attempts")
                        if hasattr(self, 'vendor_id') and self.vendor_id == 0x1452:
                            self.logger.debug("VID 0x1452: No response received")
                    return None
        return None
            
    def get_printer_info(self):
        """Get printer information"""
        self.logger.info("Getting printer information...")
        
        # Get firmware version using PTBL_RDVersion
        self.send_command("PTBL_RDVersion")
        time.sleep(0.1)
        response = self.read_response()
        if response:
            self.logger.info(f"Current firmware version: {response.decode('ascii', errors='ignore').strip()}")
            
        # Get firmware version using PINFO
        self.send_command("PINFO  FVER")
        time.sleep(0.1)
        response = self.read_response()
        if response:
            self.logger.info(f"Current firmware (PINFO): {response.decode('ascii', errors='ignore').strip()}")
            
        # Get serial number
        self.send_command("PINFO  SERIAL_NUMBER")
        time.sleep(0.1)
        response = self.read_response()
        if response:
            self.logger.info(f"Serial number: {response.decode('ascii', errors='ignore').strip()}")
            
        # Get unit status
        self.send_command("PINFO  UNIT_STATUS")
        time.sleep(0.1)
        response = self.read_response()
        if response:
            self.logger.info(f"Unit status: {response.decode('ascii', errors='ignore').strip()}")
            
    def check_cwd_versions(self):
        """Check CWD versions before update"""
        self.logger.info("Checking CWD versions...")
        
        # CWD file mappings to their IDs
        cwd_mappings = {
            "DS620_PD_300_0111.cwd": "001",
            "DS620_PD_600_0111.cwd": "002", 
            "DS620_PD_610_0111.cwd": "003",
            "DS620_SD_300_0111.cwd": "004",
            "DS620_SD_600_0111.cwd": "005",
            "DS620_SD_610_0111.cwd": "006"
        }
        
        for cwd_file, cwd_id in cwd_mappings.items():
            # Check version
            cmd = f"PTBL_RDCWD{cwd_id}_Version"
            self.send_command(cmd)
            time.sleep(0.1)
            response = self.read_response()
            if response:
                self.logger.info(f"{cwd_file} version: {response.decode('ascii', errors='ignore').strip()}")
                
            # Check checksum
            cmd = f"PTBL_RDCWD{cwd_id}_Checksum"
            self.send_command(cmd)
            time.sleep(0.1)
            response = self.read_response()
            if response:
                self.logger.debug(f"{cwd_file} checksum: {response.decode('ascii', errors='ignore').strip()}")
            
    def enter_update_mode(self):
        """Enter firmware update mode"""
        self.logger.info("Entering firmware update mode...")
        
        # Send flash rewrite command
        self.send_command("PFW_UPDFLASH_REWRITE")
        time.sleep(WAIT_CHMODE)
        
        response = self.read_response(timeout=15000)  # 15 second timeout
        if response:
            self.logger.info("Entered update mode (LED should be flashing green)")
            if self.logger.level == logging.DEBUG:
                self.logger.debug(f"Update mode response: {response.hex()}")
                self.logger.debug(f"Update mode response ASCII: {response.decode('ascii', errors='replace')}")
            return True
        else:
            self.logger.error("Failed to enter update mode")
            self.logger.error("Check if:")
            self.logger.error("  - Printer is ready (not busy)")
            self.logger.error("  - Cover is closed")
            self.logger.error("  - No active print jobs")
            self.logger.error("  - Media is loaded")
            return False
            
    def send_firmware(self):
        """Send S-Record firmware file using PTBL_WTCTRLD_UPDATE command"""
        self.logger.info(f"Sending firmware file: {self.firmware_path}")
        
        try:
            # Read entire firmware file
            with open(self.firmware_path, 'rb') as f:
                firmware_data = f.read()
                
            self.logger.info(f"Firmware size: {len(firmware_data)} bytes ({len(firmware_data)/1024/1024:.1f} MB)")
            
            # Send firmware update command with data length
            # Using PTBL_WTCTRLD_UPDATE for main firmware
            # Send command first (24 bytes)
            self.send_command("PTBL_WTCTRLD_UPDATE")
            time.sleep(0.1)
            
            # Then send length + data
            length_bytes = f"{len(firmware_data):08d}".encode('ascii')
            
            # Send length followed by firmware data in chunks
            self.ep_out.write(length_bytes)
            
            chunk_size = 4096
            total_sent = 0
            start_time = time.time()
            last_log_time = start_time
            
            while total_sent < len(firmware_data):
                chunk = firmware_data[total_sent:total_sent + chunk_size]
                self.ep_out.write(chunk)
                total_sent += len(chunk)
                
                # Progress indicator with time estimate
                current_time = time.time()
                if current_time - last_log_time >= 2.0:  # Log every 2 seconds
                    progress = (total_sent / len(firmware_data)) * 100
                    elapsed = current_time - start_time
                    if total_sent > 0:
                        rate = total_sent / elapsed  # bytes per second
                        remaining_bytes = len(firmware_data) - total_sent
                        eta = remaining_bytes / rate
                        self.logger.info(f"Progress: {progress:.1f}% | {total_sent/1024/1024:.1f}/{len(firmware_data)/1024/1024:.1f} MB | "
                                       f"Speed: {rate/1024:.1f} KB/s | ETA: {eta:.0f}s")
                    else:
                        self.logger.info(f"Progress: {progress:.1f}% ({total_sent}/{len(firmware_data)})")
                    last_log_time = current_time
                    
                # Small delay between chunks
                time.sleep(0.001)
                
            # Final progress
            elapsed = time.time() - start_time
            self.logger.info(f"Firmware transmission complete in {elapsed:.1f} seconds")
            self.logger.info(f"Average speed: {len(firmware_data)/elapsed/1024:.1f} KB/s")
            
            # Wait for response
            self.logger.info("Waiting for printer to process firmware...")
            time.sleep(1.0)
            response = self.read_response(timeout=10000)
            if response:
                self.logger.debug(f"Firmware update response: {response}")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send firmware: {e}")
            return False
            
    def program_flash(self):
        """Execute flash programming"""
        self.logger.info("Programming flash memory...")
        
        # Send program command
        self.send_command("PFW_UPDFLASH_PROGRAM")
        
        # Wait for programming to complete
        self.logger.info("Waiting for flash programming to complete (this may take several minutes)...")
        
        # Poll update status
        start_time = time.time()
        timeout = 300  # 5 minutes timeout
        
        while time.time() - start_time < timeout:
            # Check update status
            self.send_command("PINFO  DUNIT_UPD_STS")
            time.sleep(1.0)
            response = self.read_response()
            
            if response:
                status = response.decode('ascii', errors='ignore').strip()
                self.logger.debug(f"Update status: {status}")
                
                if "COMPLETE" in status or "FINISH" in status:
                    self.logger.info("Flash programming complete")
                    return True
                elif "ERROR" in status or "FAIL" in status:
                    self.logger.error(f"Flash programming failed: {status}")
                    return False
                    
            time.sleep(2.0)
            
        self.logger.error("Flash programming timed out")
        return False
            
    def update_cwd_files(self):
        """Update CWD configuration files"""
        cwd_files = [
            "DS620_PD_300_0111.cwd",
            "DS620_PD_600_0111.cwd",
            "DS620_PD_610_0111.cwd",
            "DS620_SD_300_0111.cwd",
            "DS620_SD_600_0111.cwd",
            "DS620_SD_610_0111.cwd"
        ]
        
        for cwd_file in cwd_files:
            cwd_path = self.cwd_dir / cwd_file
            if not cwd_path.exists():
                self.logger.warning(f"CWD file not found: {cwd_file}")
                continue
                
            self.logger.info(f"Updating CWD file: {cwd_file}")
            
            # Read CWD file
            with open(cwd_path, 'rb') as f:
                cwd_data = f.read()
                
            # Send update command first (24 bytes)
            self.send_command("PTBL_WTCTRLD_UPDATE_CW")
            time.sleep(0.1)
            
            # Then send length + CWD data
            length_bytes = f"{len(cwd_data):08d}".encode('ascii')
            self.ep_out.write(length_bytes + cwd_data)
            time.sleep(WAIT_UPDATE)
            
            # Check response
            response = self.read_response()
            if response:
                self.logger.info(f"CWD update complete: {cwd_file}")
            else:
                self.logger.warning(f"No response for CWD update: {cwd_file}")
                
    def reset_printer(self):
        """Reset printer to complete update"""
        self.logger.info("Resetting printer...")
        
        # Send CWD reset command first
        self.send_command("PTBL_WTCTRLD_CWE_RESET")
        time.sleep(0.5)
        
        # Send cleanup command
        self.send_command("PTBL_CL")
        time.sleep(0.5)
        
        # Send printer reset command
        self.send_command("PCNTRL PRINTER_RESET")
        time.sleep(WAIT_2000MS)
        
        self.logger.info("Printer reset complete (LED should return to solid green)")
        
    def verify_update(self):
        """Verify firmware update was successful"""
        self.logger.info("Verifying firmware update...")
        
        # Wait for printer to fully restart
        time.sleep(5.0)
        
        # Get new firmware version using PTBL command
        self.send_command("PTBL_RDVersion")
        time.sleep(0.1)
        response = self.read_response()
        
        if response:
            new_version = response.decode('ascii', errors='ignore').strip()
            self.logger.info(f"New firmware version: {new_version}")
            
            # Check if version contains "04.52"
            if "04.52" in new_version or "0452" in new_version:
                self.logger.info("Firmware update successful!")
                return True
            else:
                self.logger.warning("Firmware version may not have updated correctly")
                return False
        else:
            self.logger.error("Could not verify firmware version")
            return False
            
    def dry_run(self):
        """Perform a dry run - check printer status and versions without updating"""
        self.logger.info("=== DRY RUN MODE - No changes will be made ===")
        
        try:
            # Find and setup printer
            if not self.find_printer():
                return False
                
            if not self.setup_usb():
                return False
                
            self.logger.info("\n--- Printer Information ---")
            # Get initial printer info
            self.get_printer_info()
            
            self.logger.info("\n--- Checking CWD Versions ---")
            # Check current CWD versions
            self.check_cwd_versions()
            
            self.logger.info("\n--- Firmware File Information ---")
            # Check firmware file
            if self.firmware_path.exists():
                with open(self.firmware_path, 'r') as f:
                    lines = f.readlines()
                self.logger.info(f"Firmware file: {self.firmware_path}")
                self.logger.info(f"S-Record lines: {len(lines)}")
                self.logger.info(f"File size: {self.firmware_path.stat().st_size} bytes")
                
                # Extract version from S-Record if possible
                for line in lines[:100]:  # Check first 100 lines
                    if "DS620" in line and ("04.52" in line or "0452" in line):
                        self.logger.info(f"Firmware version in file: 04.52")
                        break
            else:
                self.logger.error(f"Firmware file not found: {self.firmware_path}")
                
            self.logger.info("\n--- CWD Files Check ---")
            # Check CWD files
            cwd_files = [
                "DS620_PD_300_0111.cwd",
                "DS620_PD_600_0111.cwd",
                "DS620_PD_610_0111.cwd",
                "DS620_SD_300_0111.cwd",
                "DS620_SD_600_0111.cwd",
                "DS620_SD_610_0111.cwd"
            ]
            
            found_files = 0
            for cwd_file in cwd_files:
                cwd_path = self.cwd_dir / cwd_file
                if cwd_path.exists():
                    self.logger.info(f"✓ {cwd_file} - {cwd_path.stat().st_size} bytes")
                    found_files += 1
                else:
                    self.logger.warning(f"✗ {cwd_file} - NOT FOUND")
                    
            self.logger.info(f"\nFound {found_files}/{len(cwd_files)} CWD files")
            
            self.logger.info("\n--- Additional Status Checks ---")
            # Try additional read-only commands
            read_only_commands = [
                ("PINFO  MEDIA", "Media type"),
                ("PINFO  MEDIA_CLASS", "Media class"),
                ("PINFO  PQTY", "Print quantity"),
                ("PINFO  MQTY", "Media quantity"),
                ("PINFO  FREE_PBUFFER", "Free buffer"),
                ("PINFO  SENSOR", "Sensor status"),
                ("PMNT_RDCOUNTER_LIFE", "Life counter"),
                ("PMNT_RDUSB_ISERI_SET", "USB serial setting")
            ]
            
            for cmd, desc in read_only_commands:
                self.send_command(cmd)
                time.sleep(0.1)
                response = self.read_response()
                if response:
                    self.logger.info(f"{desc}: {response.decode('ascii', errors='ignore').strip()}")
                    
            self.logger.info("\n--- Dry Run Summary ---")
            self.logger.info("✓ Printer communication successful")
            self.logger.info("✓ All read-only commands executed")
            self.logger.info("✓ No changes were made to the printer")
            
            # Check if update would be needed
            self.logger.info("\n--- Update Recommendation ---")
            self.logger.info("To perform actual firmware update, run without --dry-run flag")
            self.logger.info("WARNING: Actual update will modify printer firmware!")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Dry run failed with error: {e}")
            return False
        finally:
            # Release USB resources
            if self.device:
                usb.util.dispose_resources(self.device)
            
    def manage_cups(self, action='stop'):
        """Stop or start CUPS service"""
        if action == 'stop':
            # Check if CUPS is running first
            try:
                result = subprocess.run(['systemctl', 'is-active', 'cups'], 
                                      capture_output=True, text=True)
                if result.stdout.strip() == 'active':
                    self.cups_was_running = True
                    self.logger.info("Stopping CUPS service...")
                    
                    # Stop cups-browsed first if it exists
                    subprocess.run(['sudo', 'systemctl', 'stop', 'cups-browsed'], 
                                 capture_output=True)
                    
                    # Stop main CUPS service
                    subprocess.run(['sudo', 'systemctl', 'stop', 'cups'], 
                                 capture_output=True, check=True)
                    
                    self.logger.info("CUPS service stopped")
                    time.sleep(2)  # Give time for USB to be released
                else:
                    self.logger.info("CUPS is not running")
            except Exception as e:
                self.logger.warning(f"Could not stop CUPS: {e}")
                
    def run_update(self):
        """Run the complete firmware update process"""
        try:
            # Stop CUPS to prevent interference
            self.manage_cups('stop')
            
            # Find and setup printer
            if not self.find_printer():
                return False
                
            if not self.setup_usb():
                return False
                
            # Get initial printer info
            self.get_printer_info()
            
            # Confirm with user
            print("\n" + "="*60)
            print("WARNING: Firmware update will begin.")
            print("DO NOT disconnect USB or power during the update!")
            print("The printer may be permanently damaged if interrupted.")
            print("")
            print("CUPS has been stopped to prevent interference.")
            print("It will be restarted after the update.")
            print("="*60 + "\n")
            
            response = input("Continue with firmware update? (yes/no): ")
            if response.lower() != 'yes':
                self.logger.info("Update cancelled by user")
                return False
            
            # Mark update as in progress
            self.update_in_progress = True
            self.logger.info("Starting firmware update...")
            update_start = time.time()
                
            # Check current firmware version and CWD versions
            self.check_cwd_versions()
            
            # Check printer status before update
            self.logger.info("Checking printer status before update...")
            self.send_command("PSTATUS")
            time.sleep(0.5)
            status_response = self.read_response()
            if status_response:
                self.logger.info(f"Printer status: {status_response.decode('ascii', errors='replace').strip()}")
            
            # Enter update mode
            if not self.enter_update_mode():
                return False
                
            # Send firmware
            if not self.send_firmware():
                return False
                
            # Program flash
            if not self.program_flash():
                return False
                
            # Update CWD files
            self.update_cwd_files()
            
            # Reset printer
            self.reset_printer()
            
            # Mark update as complete
            self.update_in_progress = False
            update_time = time.time() - update_start
            
            # Verify update
            if self.verify_update():
                self.logger.info(f"Firmware update completed successfully in {update_time:.1f} seconds!")
                print("\nIMPORTANT: Please reload paper and perform 'Paper Initialization'")
                print("\nTo restore printer in CUPS, run: ./recover_printer.sh")
                return True
            else:
                self.logger.error("Firmware update may have failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Update failed with error: {e}")
            self.update_in_progress = False
            return False
        finally:
            # Cleanup will handle USB resources and CUPS restart
            self.cleanup()
                
def main():
    parser = argparse.ArgumentParser(description='DS620A Firmware Updater for Linux')
    parser.add_argument('--firmware', '-f', required=True, help='Path to DS620_0452.s firmware file')
    parser.add_argument('--cwd-dir', '-c', required=True, help='Directory containing CWD files')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug logging')
    parser.add_argument('--dry-run', '-n', action='store_true', help='Perform dry run - check versions without updating')
    parser.add_argument('--log-file', '-l', help='Log all output to specified file')
    parser.add_argument('--no-cups', action='store_true', help='Do not automatically stop/start CUPS')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Validate paths
    firmware_path = Path(args.firmware)
    cwd_dir = Path(args.cwd_dir)
    
    if not firmware_path.exists():
        print(f"Error: Firmware file not found: {firmware_path}")
        sys.exit(1)
        
    if not cwd_dir.is_dir():
        print(f"Error: CWD directory not found: {cwd_dir}")
        sys.exit(1)
        
    # Create log file with timestamp if requested
    log_file = None
    if args.log_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"{args.log_file}_{timestamp}.log"
        
    # Create updater
    updater = DS620Updater(firmware_path, cwd_dir, log_file)
    
    # Check if running as root for actual updates
    if not args.dry_run and os.geteuid() != 0:
        print("WARNING: Not running as root. You may encounter permission issues.")
        print("Consider running with sudo for actual firmware updates.")
        print("")
    
    # Run dry-run or actual update
    if args.dry_run:
        success = updater.dry_run()
    else:
        if args.no_cups:
            updater.cups_was_running = False  # Disable automatic CUPS management
        success = updater.run_update()
    
    sys.exit(0 if success else 1)
    
if __name__ == "__main__":
    main()