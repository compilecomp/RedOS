//! RedOS kernel — entry point (Phase 1, push 2 of 4).
//!
//! Boots from the Zig Stage-0 UEFI bootloader with a validated handoff,
//! brings up serial diagnostics, and reports the boot memory map. Threads,
//! capability manager and blind IPC arrive in push 3; this file stays the
//! composition root.
//!
//! CEP: CEP-1 | Complete (v0.2.0 scope: banner + handoff validation +
//!                   memory-map report; scheduler/IPC are v0.3.0 scope)
//! Cost: cold path; all output via polled UART.
//! Fail: panic handler halts with an explicit message on serial; every
//!       handoff inconsistency halts with a named reason (Law 6).
//! Assumes: identity mapping installed by the bootloader covers the kernel
//!          image, boot stack and handoff; interrupts are disabled at entry.

#![no_std]
#![no_main]
#![deny(missing_docs)]

mod handoff;
mod serial;

use core::arch::asm;
use core::panic::PanicInfo;
use handoff::{Handoff, MEM_RESERVED, MEM_USABLE};

/// CEP: CEP-1 | Complete
/// Cost: one-time boot path; all outputs serial-polled.
/// Fail: panics on invalid handoff (named reason printed first).
/// Assumes: called by the bootloader exactly once, RDI = &Handoff (SysV),
///          interrupts disabled, identity mapping active.
#[no_mangle]
pub extern "C" fn _start(boot: &Handoff) -> ! {
    serial::init();

    serial::print(format_args!("\n=== RedOS v0.2.0 kernel ===\n"));

    if let Err(reason) = boot.validate() {
        panic_str("handoff rejected: ", reason);
    }
    serial::print(format_args!(
        "[boot] handoff OK (version {})\n",
        boot.version
    ));
    serial::print(format_args!(
        "[boot] kernel @ {:#x}, stack top {:#x}\n",
        boot.kernel_phys_base, boot.stack_top
    ));

    report_memory_map(boot);

    serial::print(format_args!(
        "[boot] REDOS KERNEL OK — entering halt loop\n"
    ));

    halt_forever();
}

/// CEP: CEP-2 | Complete (cold diagnostic; explicit formatting cost)
/// Cost: O(mmap_len) with one formatted line per region (bounded 256).
/// Fail: cannot fail after validate().
fn report_memory_map(boot: &Handoff) {
    let mut usable_total: u64 = 0;
    let mut usable_regions: u64 = 0;

    serial::print(format_args!(
        "[boot] memory map ({} entries):\n",
        boot.mmap_len
    ));
    for e in boot.mem_entries() {
        let kind = match e.kind {
            MEM_USABLE => "usable",
            MEM_RESERVED => "reserved",
            _ => "unknown",
        };
        serial::print(format_args!(
            "  {:#018x}-{:#018x} {}\n",
            e.base,
            e.base.saturating_add(e.len),
            kind
        ));
        if e.kind == MEM_USABLE {
            usable_total = usable_total.saturating_add(e.len);
            usable_regions += 1;
        }
    }
    serial::print(format_args!(
        "[boot] usable RAM: {} KiB in {} region(s)\n",
        usable_total / 1024,
        usable_regions
    ));
}

/// CEP: CEP-1 | Complete
/// Cost: infinite hlt loop; lowest-power idle.
/// Fail: cannot fail; never returns.
fn halt_forever() -> ! {
    loop {
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) }
    }
}

/// CEP: CEP-2 | Complete (cold path)
/// Fail: halts (never returns). Used where a static message is enough.
#[cold]
fn panic_str(prefix: &str, reason: &str) -> ! {
    serial::write_str("\nKERNEL PANIC: ");
    serial::write_str(prefix);
    serial::write_str(reason);
    serial::write_str("\n");
    halt_forever();
}

/// CEP: CEP-2 | Complete (cold path)
/// Fail: halts after printing the panic reason + location.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::write_str("\nKERNEL PANIC: ");
    if let Some(loc) = info.location() {
        serial::print(format_args!("{}:{}: ", loc.file(), loc.line()));
    }
    // Formatting machinery on the cold path only (explicit cost).
    serial::print(format_args!("{}", info.message()));
    serial::write_str("\n");
    halt_forever();
}
