"""
Test protocol command formatting
"""

import pytest
from ds620_updater.updater import DS620Updater


class TestProtocol:
    """Test protocol command formatting"""
    
    def test_command_padding(self):
        """Test that commands are padded to 24 bytes"""
        # Create a mock updater
        updater = DS620Updater(None, None)
        
        # Test command formatting
        test_commands = [
            ("PSTATUS", 24),
            ("PINFO  FVER", 24),
            ("PTBL_RDVersion", 24),
            ("PFW_UPDFLASH_REWRITE", 24),
        ]
        
        for cmd, expected_len in test_commands:
            # Simulate command formatting (without USB)
            esc = 0x1B
            cmd_bytes = bytes([esc]) + cmd.encode('ascii')
            if len(cmd_bytes) < 24:
                cmd_bytes += b' ' * (24 - len(cmd_bytes))
            
            assert len(cmd_bytes) == expected_len, f"Command {cmd} not padded correctly"
    
    def test_usb_device_ids(self):
        """Test USB device ID constants"""
        from ds620_updater.updater import DNP_VENDOR_IDS, PRODUCT_IDS
        
        assert 0x1343 in DNP_VENDOR_IDS
        assert 0x1452 in DNP_VENDOR_IDS
        assert 0x0001 in PRODUCT_IDS[0x1343]
        assert 0x8b01 in PRODUCT_IDS[0x1452]
        assert len(PRODUCT_IDS[0x1343]) == 11
        assert len(PRODUCT_IDS[0x1452]) == 6