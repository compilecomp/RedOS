//! RedOS kernel — first-party 16550 UART serial driver (COM1, port 0x3F8).
//!
//! Phase 1 diagnostic channel. Zero dependencies: raw `in`/`out` port I/O
//! via inline asm, polled transmit. This is cold-path code (banner, panic,
//! IPC test diagnostics) — never on the CEP-0 hot path.
//!
//! CEP: CEP-1 | Complete (polled TX; RX unimplemented by design in Phase 1)
//! Cost: write_byte spins until transmitter-holding-register empty
//!       (bounded by UART drain time at 115200 baud ≈ 87 µs/byte worst case).
//! Fail: cannot fail; init is idempotent.
//! Assumes: COM1 exists at port 0x3F8 (QEMU x86_64 default; asserted by the
//!          boot test that reads the banner back from QEMU's -serial stdio).

use core::arch::asm;
use core::fmt;

const COM1: u16 = 0x3F8;
const DATA: u16 = COM1 + 0;
const IER: u16 = COM1 + 1;
const FIFO: u16 = COM1 + 2;
const LCR: u16 = COM1 + 3;
const MCR: u16 = COM1 + 4;
const LSR: u16 = COM1 + 5;

const LSR_THRE: u8 = 0x20;

/// CEP: CEP-1 | Complete
/// Cost: 6 port writes; O(1).
/// Fail: cannot fail. Assumes: x86_64 privileged IO (kernel ring 0).
pub fn init() {
    unsafe {
        outb(IER, 0x00); // disable UART interrupts (polled mode)
        outb(LCR, 0x80); // enable DLAB
        outb(DATA, 0x01); // divisor low: 115200 baud
        outb(IER, 0x00); // divisor high
        outb(LCR, 0x03); // 8N1, DLAB off
        outb(FIFO, 0xC7); // enable + clear FIFO, 14-byte threshold
        outb(MCR, 0x0B); // DTR | RTS | OUT2
    }
}

/// CEP: CEP-1 | Complete
/// Cost: waits for THRE then one port write; worst case ~87 µs at 115200.
/// Fail: cannot fail.
pub fn write_byte(b: u8) {
    unsafe {
        while (inb(LSR) & LSR_THRE) == 0 {
            core::hint::spin_loop();
        }
        outb(DATA, b);
    }
}

/// CEP: CEP-1 | Complete
/// Cost: O(s.len()) byte writes; translates '\n' to '\r\n' for terminals.
/// Fail: cannot fail.
pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// CEP: CEP-2 | Complete (cold-path formatting helper; cost is explicit)
/// Cost: core::fmt machinery on the caller's arguments; cold path only.
/// Fail: cannot fail (writes are infallible).
pub fn print(args: fmt::Arguments) {
    use fmt::Write;
    let mut s = Serial;
    let _ = s.write_fmt(args);
}

struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let r: u8;
    asm!("in al, dx", out("al") r, in("dx") port, options(nomem, nostack, preserves_flags));
    r
}
