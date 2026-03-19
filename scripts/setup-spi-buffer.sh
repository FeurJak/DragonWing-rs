#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# setup-spi-buffer.sh - Configure Linux spidev buffer size for larger SPI transfers
#
# The Linux spidev driver defaults to 4096 byte buffers, which is insufficient
# for camera JPEG frames (typically 5-15KB). This script configures a larger
# buffer size persistently via kernel boot parameters.
#
# Usage:
#   ./setup-spi-buffer.sh [buffer_size]
#
# Arguments:
#   buffer_size - Size in bytes (default: 16384)
#
# Examples:
#   ./setup-spi-buffer.sh          # Set to 16KB (default)
#   ./setup-spi-buffer.sh 32768    # Set to 32KB
#
# Requirements:
#   - systemd-boot (uses /etc/kernel/cmdline)
#   - Root privileges (sudo)

set -e

# Default buffer size (16KB - supports camera frames up to ~16380 bytes)
DEFAULT_BUFSIZ=16384
BUFSIZ="${1:-$DEFAULT_BUFSIZ}"

# Validate buffer size
if ! [[ "$BUFSIZ" =~ ^[0-9]+$ ]]; then
    echo "Error: Buffer size must be a positive integer"
    exit 1
fi

if [ "$BUFSIZ" -lt 4096 ]; then
    echo "Warning: Buffer size $BUFSIZ is smaller than default (4096)"
fi

if [ "$BUFSIZ" -gt 65536 ]; then
    echo "Warning: Buffer size $BUFSIZ is very large, may impact system memory"
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Re-running with sudo..."
    exec sudo "$0" "$@"
fi

# Files
CMDLINE_FILE="/etc/kernel/cmdline"
PARAM="spidev.bufsiz=$BUFSIZ"

echo "=== Linux SPI Buffer Configuration ==="
echo ""

# Check current buffer size
CURRENT_BUFSIZ=$(cat /sys/module/spidev/parameters/bufsiz 2>/dev/null || echo "unknown")
echo "Current spidev buffer size: $CURRENT_BUFSIZ bytes"
echo "Target spidev buffer size:  $BUFSIZ bytes"
echo ""

# Check if already configured in cmdline
if [ -f "$CMDLINE_FILE" ]; then
    CURRENT_CMDLINE=$(cat "$CMDLINE_FILE")
    echo "Current kernel cmdline:"
    echo "  $CURRENT_CMDLINE"
    echo ""
    
    if echo "$CURRENT_CMDLINE" | grep -q "spidev.bufsiz="; then
        # Update existing parameter
        echo "Updating existing spidev.bufsiz parameter..."
        NEW_CMDLINE=$(echo "$CURRENT_CMDLINE" | sed "s/spidev.bufsiz=[0-9]*/spidev.bufsiz=$BUFSIZ/")
    else
        # Add new parameter
        echo "Adding spidev.bufsiz parameter..."
        NEW_CMDLINE="$CURRENT_CMDLINE spidev.bufsiz=$BUFSIZ"
    fi
    
    # Write updated cmdline
    echo "$NEW_CMDLINE" > "$CMDLINE_FILE"
    echo ""
    echo "Updated kernel cmdline:"
    echo "  $NEW_CMDLINE"
else
    echo "Error: $CMDLINE_FILE not found"
    echo "This script is designed for systemd-boot systems."
    echo ""
    echo "For GRUB-based systems, add the following to /etc/default/grub:"
    echo "  GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX spidev.bufsiz=$BUFSIZ\""
    echo "Then run: sudo update-grub"
    exit 1
fi

# Regenerate boot entry
echo ""
echo "Regenerating boot entry..."

KERNEL_VERSION=$(uname -r)
VMLINUZ="/boot/vmlinuz-$KERNEL_VERSION"
INITRD="/boot/initrd.img-$KERNEL_VERSION"

if [ -f "$VMLINUZ" ] && [ -f "$INITRD" ]; then
    kernel-install add "$KERNEL_VERSION" "$VMLINUZ" "$INITRD"
    echo "Boot entry regenerated successfully."
else
    echo "Warning: Could not find kernel/initrd files for version $KERNEL_VERSION"
    echo "  Expected: $VMLINUZ"
    echo "  Expected: $INITRD"
    echo ""
    echo "You may need to regenerate the boot entry manually after reboot."
fi

echo ""
echo "=== Configuration Complete ==="
echo ""
echo "IMPORTANT: You must reboot for changes to take effect!"
echo ""
echo "After reboot, verify with:"
echo "  cat /sys/module/spidev/parameters/bufsiz"
echo "  # Should show: $BUFSIZ"
echo ""

read -p "Reboot now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Rebooting..."
    reboot
else
    echo "Remember to reboot later for changes to take effect."
fi
