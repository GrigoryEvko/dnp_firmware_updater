# DS620A Firmware Update Protocol

Reverse-engineered from IDA Pro decompilation of `cspstat64.dll` (native USB comms library)
and `CSJCX2lm.dll` (Windows language monitor). Verified against `.NET` updater call sequence.

## USB Communication

### Device Identification
| VID | PID | Model |
|-----|-----|-------|
| 0x1452 | 0x8b01 | DS620 / Citizen CX-02 |
| 0x1452 | 0x8b02 | DS620 (alternate) |
| 0x1452 | 0x9001 | DS820 |
| 0x1452 | 0x9401 | DS820DX |
| 0x1343 | 0x0003 | DS40 |
| 0x1343 | 0x0004 | DS80 |
| 0x1343 | 0x0005 | DS-RX1 |
| 0x1343 | 0xFFFF | QW410 |

Windows uses `SetupDiGetClassDevs` + `CreateFile` + `WriteFile`/`ReadFile` (raw USB class driver).
Linux equivalent: pyusb bulk OUT/IN endpoints on interface 0.

### Endpoints
- Bulk OUT: send commands and data
- Bulk IN: receive responses

### Global Mutex
`Global\CSMUTX` serializes all USB access (relevant for multi-process scenarios).

## Wire Protocol

### Command Frame Format

**ALL commands are exactly 32 bytes. NO CRLF termination.**

```
[ESC][31 bytes ASCII, space-padded]
```
Where ESC = 0x1B (decimal 27).

Three frame subtypes:

#### 1. Non-data commands (32 bytes, no payload)
```
ESC + command_text.ljust(31) = 32 bytes
```
Examples:
```
\x1bPSTATUS                        (32 bytes)
\x1bPFW_UPDFLASH_REWRITE           (32 bytes)
\x1bPCNTRL PRINTER_RESET           (32 bytes)
```

#### 2. Query commands (32 bytes, response expected)
```
Host -> Printer:  [32-byte command frame]
Printer -> Host:  [8-byte ASCII length][N bytes data]
```
Response length field is 8 ASCII decimal digits (e.g., "00000012").

Examples:
```
\x1bPINFO  FVER                    -> "00000012" + "DS620 04.52     "
\x1bPTBL_RDVersion         00000000 -> "00000008" + "04520111"
\x1bPTBL_RDCWD300_Version  00000000 -> "00000004" + "0111"
```

#### 3. Data write commands (32-byte header + payload + trailer)
```
Header:  ESC + command_text.ljust(23) + f"{data_size:08d}" = 32 bytes
Payload: raw binary data (chunked at 1MB on the wire)
Trailer: struct.pack('<I', data_size) = 4 bytes little-endian
```
Examples:
```
\x1bPFW_UPDFLASH_PROGRAM   02286804[firmware bytes...][4-byte LE size]
\x1bPTBL_WTCTRLD_UPDATE_CW 00037152[CWD bytes...][4-byte LE size]
\x1bPTBL_WTVersion         00000004[version string][4-byte LE size]
```

## Command Reference

### PSTATUS — Printer Status
```
\x1bPSTATUS                        -> 8-byte len + status code
```

### PINFO — Information Queries
```
PINFO  FVER                  Firmware version
PINFO  SERIAL_NUMBER         Serial number
PINFO  UNIT_STATUS           Unit status
PINFO  DUNIT_UPD_STS         Firmware update status (poll during flash)
PINFO  MEDIA                 Loaded media type
PINFO  MEDIA_CLASS           Media class
PINFO  MEDIA_CLASS_RFID      RFID media class
PINFO  MQTY                  Media remaining quantity
PINFO  MQTY_DEFAULT          Initial media count
PINFO  FREE_PBUFFER          Free print buffer count
PINFO  SENSOR                Sensor readings
PINFO  RESOLUTION_H          Horizontal resolution
PINFO  RESOLUTION_V          Vertical resolution
PINFO  RQTY                  Remaining quantity (high)
PINFO  PANORAMA_PRINT        Panorama capability
PINFO  CUT_MODE              Cut control status
```

### PCNTRL — Printer Control
```
PCNTRL PRINTER_RESET         Reset/initialize printer
PCNTRL CANCEL                Cancel current job
PCNTRL START                 Start printing (after image planes)
PCNTRL CUT_PAPER     00000008  Cut paper
PCNTRL CUTTER        00000008  Cutter mode
PCNTRL OVERCOAT      00000008  Overcoat/laminate mode
PCNTRL QTY           00000008  Print quantity
PCNTRL BUFFCNTRL     00000008  Buffer/retry control
PCNTRL RETENTION     00000008  Paper retention mode
PCNTRL PRINTSPEED    00000008  Print speed
PCNTRL DECURL       00000012   Decurl control
```

### PFW_UPD — Firmware Update
```
PFW_UPDFLASH_REWRITE         Enter flash rewrite mode (LED → flashing green)
PFW_UPDFLASH_PROGRAM         Send firmware data (data write command)
PFW_UPDDUNIT_REWRITE         Enter dunit rewrite mode (+8b unit ID)
PFW_UPDDUNIT_PROGRAM         Send dunit firmware data
```

### PTBL — Table Read/Write (CWD Data)
```
PTBL_RDVersion       00000000  Read CWD version
PTBL_RDCWD300_Version 00000000 Read CWD 300dpi version
PTBL_RDCWD300_Checksum 00000000 Read CWD 300dpi checksum
PTBL_RDCWD600_Version 00000000 Read CWD 600dpi version
PTBL_RDCWD600_Checksum 00000000 Read CWD 600dpi checksum
PTBL_RDCWD610_Version 00000000 Read CWD 610 version
PTBL_RDCWD610_Checksum 00000000 Read CWD 610 checksum

PTBL_WTCTRLD_UPDATE_CW       Write CWD data (data write command)
PTBL_WTCTRLD_UPDATE          Write CWD data (fallback command)
PTBL_WTVersion               Set CWD version string
PTBL_CL              00000000 Clear/finalize CWD tables
```

### PMNT — Maintenance
```
PMNT_RDCOUNTER_LIFE          Lifetime print counter
PMNT_RDCOUNTER_A             Counter A
PMNT_RDCOUNTER_B             Counter B
PMNT_RDCOUNTER_P             Counter P
PMNT_RDCOUNTER_M             Counter M
PMNT_RDCTRLD_CHKSUM  00000000 Global CWD checksum
PMNT_RDUSB_ISERI_SET         USB serial number enable
PMNT_RDSUPPORTED_MEDIA       Supported media list
PMNT_RDSTANDBY_TIME          Standby timeout
```

## Firmware Update Sequence

From `.NET` updater call sequence (decompiled via IDA strings):

```
1. connect_printer / checkPrinter
     → find USB device, verify model

2. GetFirmwVersion
     → PINFO  FVER
     → PTBL_RDVersion         00000000

3. chkCWDverAndSum
     → PTBL_RDCWD300_Version  00000000
     → PTBL_RDCWD300_Checksum 00000000
     → (repeat for CWD600, CWD610)

4. CvSetFirmwUpdateMode
     → PFW_UPDFLASH_REWRITE
     (printer LED → flashing green)

5. CvSetFirmwDataWrite
     → PFW_UPDFLASH_PROGRAM + 8-digit size + S-Record data + 4-byte LE size
     (sends firmware file as binary blob)

6. waitUpdate
     → poll PINFO  DUNIT_UPD_STS until COMPLETE/FINISH
     (flash programming takes 1-5 minutes)

7. cwdUpdate (for each CWD file)
     → PTBL_WTCTRLD_UPDATE_CW + 8-digit size + CWD data + 4-byte LE size

8. CvSetColorDataVersion
     → PTBL_WTVersion + 8-digit size + version string + 4-byte LE size

9. cwdClear / endUpdate
     → PTBL_CL                00000000
     → PCNTRL PRINTER_RESET
     (printer LED → solid green)
```

## CWD Files

Color Working Data — internal printer LUTs stored in flash ROM.

| File | Media | DPI | Size |
|------|-------|-----|------|
| DS620_PD_300_0111.cwd | Premium Digital | 300 | 37,152 bytes |
| DS620_PD_600_0111.cwd | Premium Digital | 600 | 37,152 bytes |
| DS620_PD_610_0111.cwd | Premium Digital | 610 (low speed) | 37,152 bytes |
| DS620_SD_300_0111.cwd | Standard Digital | 300 | 37,152 bytes |
| DS620_SD_600_0111.cwd | Standard Digital | 600 | 37,152 bytes |
| DS620_SD_610_0111.cwd | Standard Digital | 610 (low speed) | 37,152 bytes |

Header: `DNP    \x00` (8 bytes), followed by encrypted LUT data.

## Image Print Protocol (Reference)

For printing (not firmware update), the wire sequence is:

```
1. Poll PINFO  FREE_PBUFFER until buffer available
2. For each color plane (Y, M, C):
     PIMAGE YPLANE + 8-digit size + 1088-byte BMP header + pixel data
3. PCNTRL START
```

BMP header: 1088 bytes (0x440), signature 0x4D42, pixel offset 1088.
Image data sent as raw RGB, separated into YMC planes by host driver.
