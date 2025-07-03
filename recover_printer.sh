#!/bin/bash
# DS620 Printer Recovery Script
# Run this if the firmware update fails or printer is not detected after update

echo "=== DS620 Printer Recovery Script ==="
echo ""

# Function to check if command succeeded
check_status() {
    if [ $? -eq 0 ]; then
        echo "✓ $1 successful"
    else
        echo "✗ $1 failed"
        return 1
    fi
}

# 1. Start CUPS service
echo "1. Starting CUPS service..."
sudo systemctl start cups
check_status "CUPS start"

# 2. Start CUPS browsing service
echo ""
echo "2. Starting CUPS browsed service..."
sudo systemctl start cups-browsed 2>/dev/null
# This might not exist on all systems, so we don't check status

# 3. Wait for services to initialize
echo ""
echo "3. Waiting for services to initialize..."
sleep 3

# 4. Check if printer is detected
echo ""
echo "4. Checking for DS620 printer..."
if lsusb | grep -q "1452:8b01\|1343:"; then
    echo "✓ DS620 printer detected on USB"
    lsusb | grep -E "1452:8b01|1343:"
else
    echo "✗ DS620 printer not found on USB"
    echo "  Please check:"
    echo "  - Printer is powered on"
    echo "  - USB cable is connected"
    echo "  - Try power cycling the printer"
    exit 1
fi

# 5. Check if printer is in CUPS
echo ""
echo "5. Checking CUPS configuration..."
if lpstat -v 2>/dev/null | grep -q "dnp-ds620\|DS620"; then
    echo "✓ DS620 found in CUPS:"
    lpstat -v | grep -i "ds620\|dnp"
else
    echo "✗ DS620 not found in CUPS"
    echo ""
    echo "6. Re-adding printer to CUPS..."
    
    # Try to detect printer with lpinfo
    DEVICE_URI=$(lpinfo -v 2>/dev/null | grep -i "gutenprint.*dnp-ds620" | awk '{print $2}')
    
    if [ -n "$DEVICE_URI" ]; then
        echo "Found printer at: $DEVICE_URI"
        echo "Adding to CUPS..."
        
        # Add printer
        sudo lpadmin -p DS620_Photo_Printer -E -v "$DEVICE_URI" -m gutenprint.5.3://dnp-ds620/expert
        check_status "Printer addition"
    else
        echo "Could not auto-detect printer URI"
        echo "You may need to add it manually through CUPS web interface:"
        echo "  http://localhost:631"
    fi
fi

# 6. Test printer status
echo ""
echo "7. Testing printer status..."
if lpstat -p 2>/dev/null | grep -i ds620; then
    lpstat -p | grep -i ds620
else
    echo "No DS620 printer status available"
fi

# 7. Final instructions
echo ""
echo "=== Recovery Complete ==="
echo ""
echo "Next steps:"
echo "1. Try printing a test page:"
echo "   lp -d <printer-name> /usr/share/cups/data/testprint"
echo ""
echo "2. If printing fails, power cycle the printer:"
echo "   - Turn off printer"
echo "   - Wait 10 seconds"
echo "   - Turn on printer"
echo "   - Wait for ready LED"
echo ""
echo "3. Check printer queues:"
echo "   lpstat -o"
echo ""
echo "4. Clear any stuck jobs:"
echo "   cancel -a"
echo ""
echo "5. For web interface access:"
echo "   http://localhost:631"