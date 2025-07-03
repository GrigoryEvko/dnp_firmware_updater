# DS620A Firmware Updater for Linux

A reverse-engineered firmware updater for the DNP DS620A photo printer, designed to work on Linux systems. This tool was created by analyzing the Windows firmware update protocol and implementing a compatible Linux version.

## Features

- ✅ Full firmware update capability (v4.52)
- ✅ CWD (Color Working Data) file updates
- ✅ Dry-run mode for safe testing
- ✅ Comprehensive logging
- ✅ USB communication with retry logic
- ✅ Progress tracking during updates

## Prerequisites

- Python 3.6 or higher
- PyUSB library
- USB access permissions (sudo or udev rules)
- DS620A printer connected via USB

## Installation

### From GitHub

```bash
# Clone the repository
git clone https://github.com/GrigoryEvko/dnp_firmware_updater.git
cd dnp_firmware_updater

# Install the package
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Manual Installation

```bash
# Install dependencies
pip install pyusb

# Make the script executable
chmod +x ds620_updater/updater.py
```

## Usage

### Command Line Interface

```bash
# Dry-run mode (RECOMMENDED first step)
ds620-updater --firmware firmware/DS620_0452.s --cwd-dir firmware/ --dry-run

# Perform actual firmware update
sudo ds620-updater --firmware firmware/DS620_0452.s --cwd-dir firmware/

# With debug logging
sudo ds620-updater --firmware firmware/DS620_0452.s --cwd-dir firmware/ --debug
```

### Python API

```python
from ds620_updater import DS620Updater
from pathlib import Path

# Create updater instance
updater = DS620Updater(
    firmware_path=Path("firmware/DS620_0452.s"),
    cwd_dir=Path("firmware/")
)

# Run dry-run
updater.dry_run()

# Perform update
updater.run_update()
```

## USB Permissions

To avoid using sudo, create a udev rule:

```bash
# Create udev rule
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="1343", MODE="0666", GROUP="plugdev"' | \
    sudo tee /etc/udev/rules.d/99-dnp-ds620.rules

# Reload rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Add user to plugdev group
sudo usermod -a -G plugdev $USER
```

## Firmware Files

The `firmware/` directory contains:
- `DS620_0452.s` - Main firmware file (Motorola S-Record format)
- `DS620_PD_300_0111.cwd` - Photo Direct 300 DPI configuration
- `DS620_PD_600_0111.cwd` - Photo Direct 600 DPI configuration
- `DS620_PD_610_0111.cwd` - Photo Direct 610 DPI configuration
- `DS620_SD_300_0111.cwd` - Standard Direct 300 DPI configuration
- `DS620_SD_600_0111.cwd` - Standard Direct 600 DPI configuration
- `DS620_SD_610_0111.cwd` - Standard Direct 610 DPI configuration

## Protocol Details

The DS620A uses a text-based command protocol over USB:
- **Vendor ID**: 0x1343 (DNP)
- **Product IDs**: 0x0001-0x0009, 0x1001, 0xFFFF
- **Commands**: 24-byte fixed format (ESC + command + padding)
- **Data**: Binary transmission with 8-digit length headers

## Safety Notes

⚠️ **WARNING**: 
- Always run a dry-run first to verify printer communication
- Do not disconnect USB or power during firmware update
- Ensure stable power supply throughout the process
- Update process takes 5-10 minutes
- Printer may be permanently damaged if update is interrupted

## Troubleshooting

1. **"Printer not found"**
   - Check USB cable connection
   - Verify USB permissions (try with sudo)
   - Ensure printer is powered on

2. **"Failed to enter update mode"**
   - Printer must be idle (not printing)
   - Close printer cover
   - Try power cycling the printer

3. **"USB timeout"**
   - Check USB cable quality
   - Try a different USB port
   - Increase timeout values in debug mode

## Development

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Format code
black ds620_updater/

# Type checking
mypy ds620_updater/
```

## License

This project is released under the MIT License. See LICENSE file for details.

## Disclaimer

This is unofficial software created through reverse engineering. Use at your own risk. The authors are not responsible for any damage to your printer. This tool is not affiliated with or endorsed by DNP.

## Acknowledgments

Created by analyzing the official Windows firmware updater to enable Linux support for DS620A printer owners.