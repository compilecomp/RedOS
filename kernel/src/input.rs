//! RedOS kernel — operator input service (v0.7.0, Zero-ID identity).
//!
//! The RX half of the 16550 driver: polled reads of COM1's receive buffer
//! assembled into lines. This is the ONLY path operator secrets take —
//! the vault PIN has no kernel-side constant since v0.7.0 (the CI feeder
//! types it over the UART; on hardware the operator does). The service
//! is cooperative: while waiting for a human, callers yield via
//! `task::yield_tick` so the rest of the system keeps running; kmain
//! (slot 0) passes me=0 and tight-polls instead (nothing else runs yet).
//!
//! Privacy: PIN prompts use masked echo ('*' per character) — the
//! operator's keystrokes are never echoed verbatim, so the serial log
//! (which CI archives) carries no PIN. Grant prompts echo plainly
//! ('y'/'n' are decisions, not secrets — the log is the audit trail).
//!
//! Single-consumer-at-a-time: the kernel is cooperative and input lines
//! are sequenced by the scenario (kmain seals before spawning; tasks
//! prompt through the identity service's strict ordering). No locking
//! exists because there is no preemption (Phase 2 model, documented).
//!
//! CEP: CEP-1 | Complete (Phase 2 scope: line reads, no line editing
//!       beyond backspace; no flow control — the 16550 FIFO plus QEMU's
//!       chardev backpressure absorb the CI feeder's burst).
//! Cost: O(1) per byte (LSR poll + RBR read); O(line) per line.
//! Fail: named errors (TooLong); empty lines are the caller's retry.
//! Assumes: COM1 exists (same assumption as serial.rs); ring 0.

use crate::serial;
use core::arch::asm;

const COM1: u16 = 0x3F8;
const RBR: u16 = COM1 + 0; // receive buffer (DLAB off)
const LSR: u16 = COM1 + 5;

const LSR_DATA: u8 = 0x01; // receiver data ready

/// Echo policy for `read_line`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    /// Print one '*' per typed character (PINs — never echoed verbatim).
    Masked,
    /// Echo typed characters verbatim (grant decisions — audit trail).
    Plain,
}

/// Read one received byte if the UART has data (polled, non-blocking).
/// CEP: CEP-1 | Complete
/// Cost: one LSR read; one RBR read when data is ready.
/// Fail: None when the receiver buffer is empty (not an error — polling).
pub fn poll_byte() -> Option<u8> {
    unsafe {
        let lsr = inb(LSR);
        if lsr & LSR_DATA != 0 {
            Some(inb(RBR))
        } else {
            None
        }
    }
}

/// Cross-call CR-LF pairing state (single-consumer module, cooperative
/// kernel): set when a line ends with a bare CR; the next read then
/// skips ONE leading LF (the pair's second half) instead of reporting a
/// phantom empty line. LF-terminated lines clear it, and any non-LF
/// byte clears it too.
static mut PENDING_EOL: bool = false;

/// Read one line from the operator (blocking; cooperative).
///
/// Prints `prompt`, then consumes UART bytes until CR/LF. Returns the
/// line WITHOUT the terminator. Backspace (0x08) and DEL (0x7F) shrink
/// the line; only printable ASCII (0x20..=0x7E) is accepted. Lines
/// longer than `buf` fail with "input-too-long" — the rest of the
/// operator's line is DRAINED to its terminator first (bounded at 1024
/// bytes), so a retry starts on a coherent stream.
///
/// `me` is the caller's task slot: 0 (kmain) tight-polls (nothing else
/// is runnable before the first spawn); any other task yields between
/// polls so the scheduler stays live while the human thinks.
///
/// CEP: CEP-1 | Complete
/// Cost: O(line) byte ops + one yield per idle poll (me != 0).
/// Fail: Err("input-too-long") — the operator's line exceeded `buf`
///       (remainder drained, see above). Empty lines RETURN Ok(0);
///       callers decide their own retry policy.
/// Assumes: single consumer at a time (cooperative kernel).
pub fn read_line(
    prompt: &str,
    echo: Echo,
    me: usize,
    buf: &mut [u8],
) -> Result<usize, &'static str> {
    serial::print(format_args!("{}", prompt));
    let mut n = 0usize;
    loop {
        match poll_byte() {
            Some(b) => {
                // CR-LF pairing: a leading LF right after a bare-CR line
                // end belongs to the previous line — swallow it.
                let pending = unsafe { core::ptr::read(core::ptr::addr_of!(PENDING_EOL)) };
                if pending && b == b'\n' {
                    unsafe {
                        core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDING_EOL), false);
                    }
                    continue;
                }
                let is_eol = b == b'\r' || b == b'\n';
                if is_eol {
                    // A bare CR may be followed by LF (paired on the next
                    // read); an LF terminates definitively.
                    unsafe {
                        core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDING_EOL), b == b'\r');
                    }
                    serial::print(format_args!("\n"));
                    return Ok(n);
                }
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDING_EOL), false);
                }
                if b == 0x08 || b == 0x7F {
                    if n > 0 {
                        n -= 1;
                        if echo == Echo::Plain {
                            serial::print(format_args!("\x08 \x08"));
                        }
                    }
                    continue;
                }
                if (0x20..=0x7E).contains(&b) {
                    if n >= buf.len() {
                        // Drain to the line's terminator (bounded) so the
                        // retry consumes a coherent stream, then fail.
                        let mut dropped = b;
                        let mut drained = 0usize;
                        while dropped != b'\r' && dropped != b'\n' && drained < 1024 {
                            match poll_byte() {
                                Some(nb) => {
                                    dropped = nb;
                                    drained += 1;
                                }
                                None => {
                                    if me != 0 {
                                        crate::task::yield_tick(me);
                                    } else {
                                        core::hint::spin_loop();
                                    }
                                }
                            }
                        }
                        return Err("input-too-long");
                    }
                    buf[n] = b;
                    n += 1;
                    match echo {
                        Echo::Masked => serial::print(format_args!("*")),
                        Echo::Plain => serial::print(format_args!("{}", b as char)),
                    }
                }
                // Non-printable, non-control bytes are dropped (no echo).
            }
            None => {
                // Idle poll: keep the system alive while the human types.
                if me != 0 {
                    crate::task::yield_tick(me);
                } else {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let r: u8;
    asm!("in al, dx", out("al") r, in("dx") port, options(nomem, nostack, preserves_flags));
    r
}
