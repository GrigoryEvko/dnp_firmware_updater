# DS620A Firmware Update Protocol Documentation

This document describes the reverse-engineered protocol used by the DNP DS620A photo printer for firmware updates.

## USB Communication

### Device Identification
- **Vendor ID**: 0x1343 (DNP - Dai Nippon Printing)
- **Product IDs**: 
  - 0x0001 through 0x0009
  - 0x1001
  - 0xFFFF

### Endpoints
- Uses standard USB bulk transfer endpoints
- OUT endpoint for sending commands/data
- IN endpoint for receiving responses

## Command Protocol

### Command Format
All commands follow a fixed 24-byte format:
```
[ESC][Command Text][Padding Spaces]
```

- **ESC**: 0x1B (Escape character)
- **Command Text**: ASCII command string
- **Padding**: Space characters (0x20) to reach exactly 24 bytes total
- **Line Ending**: CR+LF (0x0D 0x0A) after command

### Command Categories

#### 1. PINFO (Printer Information)
Read-only commands for querying printer status:
```
PINFO  FVER                 # Firmware version
PINFO  SERIAL_NUMBER        # Serial number
PINFO  UNIT_STATUS          # Unit status
PINFO  DUNIT_UPD_STS        # Update status
PINFO  MEDIA                # Media type
PINFO  MEDIA_CLASS          # Media class
PINFO  FREE_PBUFFER         # Free print buffer
```

#### 2. PCNTRL (Printer Control)
Control commands for printer operations:
```
PCNTRL PRINTER_RESET        # Reset printer
PCNTRL START                # Start operation
PCNTRL CANCEL               # Cancel operation
```

#### 3. PFW (Printer Firmware)
Firmware update specific commands:
```
PFW_UPDFLASH_REWRITE        # Enter firmware update mode
PFW_UPDFLASH_PROGRAM        # Execute flash programming
PFW_UPDDUNIT_REWRITE        # Display unit rewrite mode
PFW_UPDDUNIT_PROGRAM        # Display unit programming
```

#### 4. PTBL (Printer Table)
Table/data management commands:
```
PTBL_RDVersion              # Read firmware version
PTBL_WTCTRLD_UPDATE         # Write control data update
PTBL_WTCTRLD_UPDATE_CW      # Write CWD file update
PTBL_WTCTRLD_CWE_RESET      # Reset after CWD update
PTBL_CL                     # Cleanup command
```

#### 5. PMNT (Printer Maintenance)
Maintenance and counter commands:
```
PMNT_RDCOUNTER_LIFE         # Read life counter
PMNT_RDUSB_ISERI_SET        # Read USB serial setting
```

### Data Transmission

For commands that send data (firmware or CWD files):
1. Send 24-byte command
2. Send 8-digit ASCII length (e.g., "00234567")
3. Send binary data

Example:
```
[ESC]PTBL_WTCTRLD_UPDATE    [00234567][binary data...]
```

## Update Sequence

### 1. Initialization
```
→ PSTATUS
← Response
→ PINFO  FVER
← Current version
```

### 2. Enter Update Mode
```
→ PFW_UPDFLASH_REWRITE
← ACK (LED changes to flashing green)
```

### 3. Send Firmware
```
→ PTBL_WTCTRLD_UPDATE
→ [8-digit size][S-Record data]
← Response after complete
```

### 4. Program Flash
```
→ PFW_UPDFLASH_PROGRAM
← Status
→ PINFO  DUNIT_UPD_STS (poll until complete)
← Status updates...
```

### 5. Update CWD Files
For each CWD file:
```
→ PTBL_WTCTRLD_UPDATE_CW
→ [8-digit size][CWD binary data]
← Response
```

### 6. Finalize
```
→ PTBL_WTCTRLD_CWE_RESET
← ACK
→ PTBL_CL
← ACK
→ PCNTRL PRINTER_RESET
← Reset complete (LED returns to solid green)
```

## CWD File Structure

CWD (Color Working Data) files contain printer configuration:
- Fixed size: 37,152 bytes
- Header: "DNP    " (8 bytes)
- Followed by encrypted/compressed configuration data

File naming convention:
- PD = Photo Direct mode
- SD = Standard Direct mode
- 300/600/610 = DPI resolution
- 0111 = Version number

## Error Handling

- Commands may timeout (typical timeout: 5 seconds)
- Retry failed reads up to 3 times
- Monitor DUNIT_UPD_STS during flash programming
- Check for ERROR/FAIL status responses

## Safety Considerations

1. Always verify printer status before update
2. Ensure stable power and USB connection
3. Do not interrupt during flash programming
4. LED indicators:
   - Solid green: Normal operation
   - Flashing green: Update mode
   - Red: Error condition