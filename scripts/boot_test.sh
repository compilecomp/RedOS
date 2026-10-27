#!/bin/sh
# RedOS headless boot test (CEP-2 tooling).
#
# Boots the ESP image under QEMU/OVMF, drives the operator input path
# (v0.7.0: the vault PIN and the permission prompts arrive over the
# UART — the kernel binary contains no PIN), captures the serial log,
# and asserts the full success-banner set. Exit 0 = boot chain +
# memory physics + KMS vault + zero-ID identity all verified; exit 1 =
# failure with full serial log.
#
# The test PIN "sovereign-pin-01" is TEST HARNESS data (public, like the
# wrong-PIN vector inside the kernel): the operator on a real system
# types a secret the repository never sees. `make secret-audit` proves
# the kernel binary carries no such string.
set -eu
cd "$(dirname "$0")/.."

OVMF_DIR="${OVMF_DIR:-/usr/share/OVMF}"
QEMU_BIN="${QEMU:-qemu-system-x86_64}"
LOG=build/qemu_boot.log
FIFO=build/qemu_stdin
# CI PIN (test harness data; see header note).
TEST_PIN="sovereign-pin-01"

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

rm -f "$FIFO"
mkfifo "$FIFO"

# Feeder: watches the serial log for the operator prompts and answers
# them through QEMU's stdin (the guest's COM1). Each answer is written
# only after its prompt text is OBSERVED in the log — the guest is
# polling the UART at that moment, so the 16550 FIFO cannot overflow.
feeder() {
    pos=1
    feed() {
        # $1 = prompt pattern, $2 = answer line
        i=0
        while [ "$i" -lt 2000 ]; do
            if tail -c +"$pos" "$LOG" 2>/dev/null | grep -aq -- "$1"; then
                pos=$(wc -c < "$LOG")
                printf '%s\n' "$2" >&3
                return 0
            fi
            sleep 0.3
            i=$((i + 1))
        done
        return 1
    }
    feed "VAULT-PIN:" "$TEST_PIN"        || return 1
    feed "UNLOCK-PIN:" "$TEST_PIN"       || return 1
    feed "PROMPT-LEASE" "y"              || return 1
    feed "PROMPT-DISK" "n"               || return 1
    # Remaining runtime: just keep the pipe open until the judges finish.
    sleep 300
    return 0
}

# Hold the FIFO open (RDWR: never blocks) so QEMU's stdin is live from
# the first byte and stays alive for the whole run. Opened BEFORE the
# feeder subshell is forked so it inherits fd 3.
exec 3<>"$FIFO"
feeder &
FEEDER_PID=$!

set +e
timeout -k 5 240 "$QEMU_BIN" \
    -machine q35 -m 512M -display none -no-reboot -nic none -serial stdio \
    -L "${QEMU_DATA_DIR:-/usr/share/qemu}" \
    $PFLASH_ARGS \
    -drive format=raw,file=build/esp.img <&3 > "$LOG" 2>&1
status=$?
kill "$FEEDER_PID" 2>/dev/null
set -e

# Kernel enters a halt loop, so timeout(124) is the expected exit path.
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
    echo "BOOT TEST FAILED: qemu exited $status"
    cat "$LOG"
    exit 1
fi

if grep -q "REDOS MEMPHY ISOLATION PASS" "$LOG" \
   && grep -q "REDOS MEMPHY WIPE PASS" "$LOG" \
   && grep -q "REDOS MEMPHY LOCK PASS" "$LOG" \
   && grep -q "REDOS MEMPHY ZERO-COPY PASS" "$LOG" \
   && grep -q "REDOS MEMPHY REVOKE PASS" "$LOG" \
   && grep -q "REDOS MEMPHY TEST COMPLETE" "$LOG" \
   && grep -q "REDOS KMS SEAL PASS" "$LOG" \
   && grep -q "REDOS KMS UNLOCK PASS" "$LOG" \
   && grep -q "REDOS KMS LEASE PASS" "$LOG" \
   && grep -q "REDOS RAMDISK ROUND-TRIP PASS" "$LOG" \
   && grep -q "REDOS RAMDISK CIPHERTEXT PASS" "$LOG" \
   && grep -q "REDOS KMS DURESS PASS" "$LOG" \
   && grep -q "REDOS KMS TEST COMPLETE" "$LOG" \
   && grep -q "REDOS RNG-POLICY PASS" "$LOG" \
   && grep -q "REDOS INPUT PASS" "$LOG" \
   && grep -q "REDOS IDNT MAC-REFUSED" "$LOG" \
   && grep -q "REDOS IDNT HASH-REFUSED" "$LOG" \
   && grep -q "REDOS IDNT SPAWN PASS" "$LOG" \
   && grep -q "REDOS IDNT W^X PASS" "$LOG" \
   && grep -q "REDOS IDNT POLICY-REFUSED" "$LOG" \
   && grep -q "REDOS IDNT LEASE-BOUND PASS" "$LOG" \
   && grep -q "REDOS IDNT LEASE-EXPIRED PASS" "$LOG" \
   && grep -q "REDOS IDNT PROMPT-DENIED PASS" "$LOG" \
   && grep -q "REDOS IDNT TRACKER PASS" "$LOG" \
   && grep -q "REDOS IDNT TEST COMPLETE" "$LOG" \
   && grep -q "REDOS GDT-TSS PASS" "$LOG" \
   && grep -q "REDOS WX-KERNEL PASS" "$LOG" \
   && grep -q "REDOS PCID PASS" "$LOG" \
   && grep -q "REDOS FASTPATH CYCLES" "$LOG" \
   && grep -q "REDOS RING3 PASS" "$LOG" \
   && grep -q "REDOS FASTPATH PASS" "$LOG" \
   && grep -q "REDOS USRFAULT PASS" "$LOG" \
   && grep -q "REDOS GLASSWALL PASS" "$LOG" \
   && grep -q "REDOS-BOOT" "$LOG" \
   && ! grep -q "FAIL:" "$LOG" \
   && ! grep -q "KERNEL PANIC" "$LOG" \
   && ! grep -q "KERNEL FAULT" "$LOG"; then
    echo "BOOT TEST PASSED (memory-physics + KMS vault + zero-ID identity + fast-path/glass-wall banners verified)"
    grep -aE "REDOS-BOOT|MEMPHY|KMS|IDNT|RNG-POLICY|INPUT PASS|disk|GDT|WX|PCID|RING3|FASTPATH|USRFAULT|GLASSWALL" "$LOG" | head -40
    exit 0
fi

echo "BOOT TEST FAILED — serial log follows:"
cat "$LOG"
exit 1
