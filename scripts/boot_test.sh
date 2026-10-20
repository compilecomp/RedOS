#!/bin/sh
# RedOS headless boot test (CEP-2 tooling).
#
# Boots the ESP image under QEMU/OVMF, captures the serial log, and asserts
# the kernel success banner (which transitively proves bootloader success:
# the kernel cannot print without the loader having handed off correctly).
# Exit 0 = boot chain verified; exit 1 = failure with full serial log.
set -eu
cd "$(dirname "$0")/.."

OVMF_DIR="${OVMF_DIR:-/usr/share/OVMF}"
QEMU_BIN="${QEMU:-qemu-system-x86_64}"
LOG=build/qemu_boot.log

cp "$OVMF_DIR/OVMF_VARS_4M.fd" build/OVMF_VARS.fd 2>/dev/null || true

PFLASH_ARGS=""
if [ -f "$OVMF_DIR/OVMF_CODE_4M.fd" ]; then
    # Split code/vars firmware (Debian trixie style)
    PFLASH_ARGS="-drive if=pflash,format=raw,readonly=on,file=$OVMF_DIR/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=build/OVMF_VARS.fd"
elif [ -f "$OVMF_DIR/OVMF.fd" ]; then
    # Combined single-file firmware (Ubuntu style): -bios mode
    PFLASH_ARGS="-bios $OVMF_DIR/OVMF.fd"
else
    echo "BOOT TEST FAILED: no OVMF firmware found in $OVMF_DIR"
    exit 1
fi

set +e
timeout -k 5 150 "$QEMU_BIN" \
    -machine q35 -m 512M -display none -no-reboot -nic none -serial stdio \
    -L "${QEMU_DATA_DIR:-/usr/share/qemu}" \
    $PFLASH_ARGS \
    -drive format=raw,file=build/esp.img > "$LOG" 2>&1
status=$?
set -e
# Kernel enters a halt loop, so timeout(124) is the expected exit path.
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
    echo "BOOT TEST FAILED: qemu exited $status"
    cat "$LOG"
    exit 1
fi

if grep -q "REDOS KERNEL OK" "$LOG" && grep -q "REDOS-BOOT" "$LOG"; then
    echo "BOOT TEST PASSED (serial banners verified)"
    grep -E "REDOS-BOOT|RedOS|usable RAM|REDOS KERNEL" "$LOG" | head -12
    exit 0
fi

echo "BOOT TEST FAILED — serial log follows:"
cat "$LOG"
exit 1
