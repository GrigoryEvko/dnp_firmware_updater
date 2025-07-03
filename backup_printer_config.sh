#!/bin/bash
# DS620 Printer Configuration Backup Script
# Run this before firmware update to save current configuration

BACKUP_DIR="printer_backup_$(date +%Y%m%d_%H%M%S)"

echo "=== DS620 Printer Configuration Backup ==="
echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# 1. Save CUPS printer list
echo ""
echo "1. Saving CUPS printer configuration..."
lpstat -v > "$BACKUP_DIR/cups_printers.txt" 2>&1
echo "   Saved to: $BACKUP_DIR/cups_printers.txt"

# 2. Save printer options for DS620
echo ""
echo "2. Saving printer options..."
for printer in $(lpstat -v | grep -i "ds620\|dnp" | cut -d: -f1 | cut -d' ' -f3); do
    echo "   Saving options for: $printer"
    lpoptions -p "$printer" -l > "$BACKUP_DIR/options_${printer}.txt" 2>&1
    lpstat -p "$printer" -l > "$BACKUP_DIR/status_${printer}.txt" 2>&1
done

# 3. Save USB device info
echo ""
echo "3. Saving USB device information..."
lsusb -v -d 1452:8b01 > "$BACKUP_DIR/usb_device_1452.txt" 2>&1
lsusb -v -d 1343: > "$BACKUP_DIR/usb_device_1343.txt" 2>&1
lsusb > "$BACKUP_DIR/usb_devices_all.txt" 2>&1

# 4. Save kernel module info
echo ""
echo "4. Saving kernel module information..."
lsmod | grep -E "usb|lp" > "$BACKUP_DIR/kernel_modules.txt" 2>&1

# 5. Create restore script
echo ""
echo "5. Creating restore script..."
cat > "$BACKUP_DIR/restore_config.sh" << 'EOF'
#!/bin/bash
# Restore printer configuration

echo "=== Restoring DS620 Printer Configuration ==="
echo ""
echo "Available printers in backup:"
cat cups_printers.txt

echo ""
echo "To restore a printer, use:"
echo "  sudo lpadmin -p PRINTER_NAME -E -v DEVICE_URI -m DRIVER_NAME"
echo ""
echo "Example based on your backup:"
grep "ds620\|dnp" cups_printers.txt | while read line; do
    printer=$(echo "$line" | cut -d: -f1 | cut -d' ' -f3)
    uri=$(echo "$line" | cut -d' ' -f2-)
    echo "sudo lpadmin -p $printer -E -v $uri -m gutenprint.5.3://dnp-ds620/expert"
done
EOF
chmod +x "$BACKUP_DIR/restore_config.sh"

# 6. Summary
echo ""
echo "=== Backup Complete ==="
echo "Backup saved to: $BACKUP_DIR/"
echo ""
echo "Contents:"
ls -la "$BACKUP_DIR/"
echo ""
echo "Before updating firmware:"
echo "1. Review the backup files"
echo "2. Note any custom printer settings"
echo "3. Keep this backup until update is verified"
echo ""
echo "After updating firmware:"
echo "1. Run ./recover_printer.sh to restore CUPS"
echo "2. Check $BACKUP_DIR/restore_config.sh for manual restore commands"