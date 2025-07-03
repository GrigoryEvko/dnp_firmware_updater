#!/usr/bin/env python3
"""
DS620A Firmware Updater for Linux
Based on reverse engineering of DNP DS620A firmware update protocol
"""

import sys
import time
import argparse
import logging
from pathlib import Path

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
    def __init__(self, firmware_path, cwd_dir):
        self.firmware_path = Path(firmware_path)
        self.cwd_dir = Path(cwd_dir)
        self.device = None
        self.ep_out = None
        self.ep_in = None
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def find_printer(self):
        """Find DS620A printer via USB"""
        for vid in DNP_VENDOR_IDS:
            for pid in PRODUCT_IDS.get(vid, []):
                self.device = usb.core.find(idVendor=vid, idProduct=pid)
                if self.device:
                    self.logger.info(f"Found DS620A printer: VID={hex(vid)}, PID={hex(pid)}")
                    return True
        
        self.logger.error("DS620A printer not found. Please ensure it's connected via USB.")
        self.logger.error("Looking for VID:PID combinations: 1343:xxxx and 1452:xxxx")
        return False
        
    def setup_usb(self):
        """Setup USB communication endpoints"""
        try:
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
            
            # Initialize printer communication
            self.initialize_printer()
            
            return True
            
        except Exception as e:
            self.logger.error(f"USB setup failed: {e}")
            return False
            
    def initialize_printer(self):
        """Initialize printer communication"""
        self.logger.info("Initializing printer communication...")
        
        # Send STATUS command to verify communication
        self.send_command("PSTATUS")
        time.sleep(0.5)
        response = self.read_response()
        
        if response:
            self.logger.info("Printer communication initialized")
        else:
            self.logger.warning("No response to STATUS command, continuing anyway...")
            
    def send_command(self, command, data=None):
        """Send command to printer"""
        # Format: ESC + command (padded to 24 bytes total) + data + CRLF
        # Commands already include the 'P' prefix where needed
        cmd_bytes = bytes([ESC]) + command.encode('ascii')
        
        # Ensure command is exactly 23 bytes (24 total with ESC)
        if len(cmd_bytes) < 24:
            cmd_bytes += b' ' * (24 - len(cmd_bytes))
        
        if data:
            cmd_bytes += data
        cmd_bytes += CRLF
        
        self.logger.debug(f"Sending: {cmd_bytes}")
        self.ep_out.write(cmd_bytes)
        
    def read_response(self, timeout=5000, retry_count=3):
        """Read response from printer with retry logic"""
        for attempt in range(retry_count):
            try:
                response = self.ep_in.read(1024, timeout)
                return bytes(response)
            except usb.core.USBTimeoutError:
                if attempt < retry_count - 1:
                    self.logger.debug(f"Read timeout, retrying... ({attempt + 1}/{retry_count})")
                    time.sleep(0.1)
                else:
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
        
        response = self.read_response()
        if response:
            self.logger.info("Entered update mode (LED should be flashing green)")
            return True
        else:
            self.logger.error("Failed to enter update mode")
            return False
            
    def send_firmware(self):
        """Send S-Record firmware file using PTBL_WTCTRLD_UPDATE command"""
        self.logger.info(f"Sending firmware file: {self.firmware_path}")
        
        try:
            # Read entire firmware file
            with open(self.firmware_path, 'rb') as f:
                firmware_data = f.read()
                
            self.logger.info(f"Firmware size: {len(firmware_data)} bytes")
            
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
            
            while total_sent < len(firmware_data):
                chunk = firmware_data[total_sent:total_sent + chunk_size]
                self.ep_out.write(chunk)
                total_sent += len(chunk)
                
                # Progress indicator
                progress = (total_sent / len(firmware_data)) * 100
                if total_sent % (chunk_size * 10) == 0:
                    self.logger.info(f"Progress: {progress:.1f}% ({total_sent}/{len(firmware_data)})")
                    
                # Small delay between chunks
                time.sleep(0.001)
                
            self.logger.info("Firmware transmission complete")
            
            # Wait for response
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
            
    def run_update(self):
        """Run the complete firmware update process"""
        try:
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
            print("="*60 + "\n")
            
            response = input("Continue with firmware update? (yes/no): ")
            if response.lower() != 'yes':
                self.logger.info("Update cancelled by user")
                return False
                
            # Check current firmware version and CWD versions
            self.check_cwd_versions()
            
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
            
            # Verify update
            if self.verify_update():
                self.logger.info("Firmware update completed successfully!")
                print("\nIMPORTANT: Please reload paper and perform 'Paper Initialization'")
                return True
            else:
                self.logger.error("Firmware update may have failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Update failed with error: {e}")
            return False
        finally:
            # Release USB resources
            if self.device:
                usb.util.dispose_resources(self.device)
                
def main():
    parser = argparse.ArgumentParser(description='DS620A Firmware Updater for Linux')
    parser.add_argument('--firmware', '-f', required=True, help='Path to DS620_0452.s firmware file')
    parser.add_argument('--cwd-dir', '-c', required=True, help='Directory containing CWD files')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug logging')
    parser.add_argument('--dry-run', '-n', action='store_true', help='Perform dry run - check versions without updating')
    
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
        
    # Create updater
    updater = DS620Updater(firmware_path, cwd_dir)
    
    # Run dry-run or actual update
    if args.dry_run:
        success = updater.dry_run()
    else:
        success = updater.run_update()
    
    sys.exit(0 if success else 1)
    
if __name__ == "__main__":
    main()