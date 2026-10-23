//! RedOS kernel — Interrupt Descriptor Table, exception handling, and the
//! safe-probe protocol (Phase 2).
//!
//! Phase 2 runs with interrupts disabled (maskable IRQs stay masked; IF=0).
//! Exceptions (divide/#UD/#GP/#PF…) are NOT gated by IF: they are delivered
//! through the IDT regardless. This module installs handlers for:
//!
//! * `#PF` (14) — the heart of hardware-level revocation. Two outcomes:
//!     1. **Probe path**: a `probe_read`/`probe_write` was armed and the
//!        faulting CR2 matches its expectation → the handler rewires the
//!        trap frame's RIP to the probe's fixup label and the probe
//!        returns `None` ("Access Denied"). No panic, no reboot — exactly
//!        the redOS kill-switch semantics: the operation is dropped and
//!        the app sees a generic denial.
//!     2. **Unexpected path**: a genuine kernel bug → print CR2/error
//!        code/RIP and halt (fail-fast; a faulting kernel must never
//!        continue with corrupt state).
//! * `#GP` (13), `#UD` (6) and a catch-all — always fail-fast (print + halt).
//!
//! The probe protocol (single-tasking, interrupts disabled, cooperative —
//! all preconditions that make the tiny global arm/fixup pair race-free):
//!
//! ```text
//! probe_read(addr):
//!   FIXUP := address of fixup label; EXPECTED := addr
//!   rax := 0                       (fault flag = 0 = success)
//!   mov val, [addr]                ← the probe; faults if unmapped
//!   jmp done
//! 1:                               ← FIXUP lands here (rax == 1 via frame)
//! done:
//! ```
//!
//! The #PF stub pushes rax/rdi (16 bytes), calls the Rust handler with a
//! `&mut TrapFrame` (which points INTO the hardware iret frame) and CR2,
//! then pops, skips the error code, and `iretq`s. The handler may rewrite
//! `frame.rip` (fixup) — that is the entire resumption mechanism.
//!
//! CEP: CEP-1 | Complete
//! Cost: probe = ~8 instructions + (on fault) one exception round-trip.
//! Fail: unexpected faults halt with a named forensic line.
//! Assumes: long mode; ring 0; the CS selector is discovered at runtime
//!          (the bootloader hands off on OVMF's 64-bit code segment).

use crate::serial;
use core::arch::global_asm;
use core::ptr::addr_of_mut;

// The #PF stub: hardware frame ([err][rip][cs][rfl][rsp][ss]) + two pushes.
// TrapFrame mirrors that exact stack image (rdi@0 … ss@56).
//
// Stack alignment: an exception can fire with rsp ≡ anything (mod 16); the
// SysV ABI requires callee entry rsp ≡ 8 (mod 16). The stub therefore
// aligns rsp below the call and restores it from the frame pointer before
// the pops/iretq — the standard kernel-entry dance.
global_asm!(
    ".section .text",
    ".globl redos_pf_stub",
    "redos_pf_stub:",
    "    push rax",
    "    push rdi",
    "    mov rdi, rsp",          // arg1: &TrapFrame
    "    mov rsi, cr2",          // arg2: CR2
    "    and rsp, -16",          // SysV callee alignment
    "    call redos_pf_handler",
    "    mov rsp, rdi",          // restore pre-call rsp (frame base)
    "    pop rdi",
    "    pop rax",
    "    add rsp, 8",            // discard #PF error code
    "    iretq",
    // #GP (13): error code on stack.
    ".globl redos_gp_stub",
    "redos_gp_stub:",
    "    push rax",
    "    push rdi",
    "    mov rdi, rsp",
    "    mov esi, 13",
    "    and rsp, -16",
    "    call redos_fault_halt",
    "1:  jmp 1b",
    // #UD (6): no error code on stack.
    ".globl redos_ud_stub",
    "redos_ud_stub:",
    "    push rax",
    "    push rdi",
    "    mov rdi, rsp",
    "    mov esi, 6",
    "    and rsp, -16",
    "    call redos_fault_halt",
    "1:  jmp 1b",
);

/// Fail-fast handler for #GP/#UD (never returns). `_frame` is kept for
/// future forensics; today the handler prints the vector and halts.
#[no_mangle]
pub extern "C" fn redos_fault_halt(_frame: *mut TrapFrame, vector: u64) -> ! {
    serial::print(format_args!(
        "\nKERNEL FAULT: unexpected exception #{}\n",
        vector
    ));
    crate::halt_forever();
}

/// The trap frame as it lies on the stack when the Rust handler runs
/// (stub pushed rax/rdi on top of the hardware iret frame + error code).
#[repr(C)]
pub struct TrapFrame {
    pub rdi: u64,
    pub rax: u64,
    pub err: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// --- Probe protocol state --------------------------------------------------

/// Fixup RIP the handler jumps to for an armed probe (0 = none armed).
static mut FIXUP: u64 = 0;
/// Expected CR2 of the armed probe (defensive match).
static mut EXPECTED: u64 = 0;
/// Armed flag (belt and braces: FIXUP != 0 implies armed).
static mut ARMED: u32 = 0;

/// The Rust #PF handler (called from the stub above).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) (two global compares on the probe path).
/// Fail: unexpected faults print forensics and halt.
#[no_mangle]
pub extern "C" fn redos_pf_handler(frame: *mut TrapFrame, cr2: u64) {
    unsafe {
        let f = &mut *frame;
        if ARMED == 1 && FIXUP != 0 && cr2 == EXPECTED {
            // Kill-switch semantics: drop the operation, resume at the
            // fixup with rax=1 ("faulted"). The app sees a generic denial.
            f.rip = FIXUP;
            f.rax = 1;
            ARMED = 0;
            return;
        }
    }
    serial::write_str("\nKERNEL FAULT: unexpected #PF\n");
    serial::print(format_args!(
        "  cr2={:#018x} err={:#x} rip={:#018x} rsp={:#018x}\n",
        cr2,
        unsafe { (*frame).err },
        unsafe { (*frame).rip },
        unsafe { (*frame).rsp }
    ));
    serial::print(format_args!(
        "  err decode: {} {} {} {} {} {}\n",
        if unsafe { (*frame).err } & 1 != 0 { "prot-violation" } else { "not-present" },
        if unsafe { (*frame).err } & 2 != 0 { "write" } else { "read" },
        if unsafe { (*frame).err } & 4 != 0 { "user" } else { "supervisor" },
        if unsafe { (*frame).err } & 8 != 0 { "reserved-bit" } else { "-" },
        if unsafe { (*frame).err } & 16 != 0 { "inst-fetch" } else { "-" },
        "-" // (PKU bit 5 unused in Phase 2)
    ));
    crate::halt_forever();
}

// (redos_fault_halt is defined once, above, next to the #PF handler)

// --- IDT construction -------------------------------------------------------

const IDT_ENTRIES: usize = 256;

/// 16-byte IDT gate (low, mid, high words + attrs).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Gate {
    lo: u16,
    sel: u16,
    ist: u8,
    attr: u8,
    mid: u16,
    hi: u32,
    zero: u32,
}

static mut IDT: [Gate; IDT_ENTRIES] = [Gate {
    lo: 0,
    sel: 0,
    ist: 0,
    attr: 0,
    mid: 0,
    hi: 0,
    zero: 0,
}; IDT_ENTRIES];

/// 10-byte IDTR image: limit@0, base@2 — the hardware layout is PACKED
/// (no padding; a repr(C) struct would put base@8 and the CPU would read
/// garbage — observed and fixed in v0.5.0 bring-up).
#[repr(C, packed(1))]
struct IdtPtr {
    limit: u16,
    base: u64,
}

static mut IDTP: IdtPtr = IdtPtr { limit: 0, base: 0 };

extern "C" {
    fn redos_pf_stub();
    fn redos_gp_stub();
    fn redos_ud_stub();
}

fn set_gate(n: usize, handler: u64, sel: u16) {
    unsafe {
        let g = &mut IDT[n];
        g.lo = handler as u16;
        g.sel = sel;
        g.ist = 0;
        g.attr = 0x8E; // present, ring-0, interrupt gate
        g.mid = (handler >> 16) as u16;
        g.hi = (handler >> 32) as u32;
        g.zero = 0;
    }
}

/// Build the IDT and lidt it. Every vector gets the halt stub by default;
/// #PF gets the probe-aware handler, #GP/#UD get named halt stubs.
///
/// CEP: CEP-1 | Complete
/// Cost: one-time boot path (256 gate writes).
/// Fail: cannot fail.
/// Assumes: long mode; the current CS is a 64-bit code segment.
pub fn init() {
    // Discover the live code segment (OVMF hands off on its own selector;
    // hard-coding 0x08 or 0x38 would be a portability lie).
    let cs32: u32;
    unsafe {
        core::arch::asm!("mov {0:e}, cs", lateout(reg) cs32, options(nomem, nostack));
    }
    let cs = cs32 as u16;

    let pf = redos_pf_stub as *const () as u64;
    let gp = redos_gp_stub as *const () as u64;
    let ud = redos_ud_stub as *const () as u64;
    let halt = pf; // catch-all: an unexpected #PF is as fatal as anything
    for i in 0..IDT_ENTRIES {
        match i {
            6 => set_gate(i, ud, cs),
            13 => set_gate(i, gp, cs),
            14 => set_gate(i, pf, cs),
            _ => set_gate(i, halt, cs),
        }
    }
    unsafe {
        IDTP.limit = (IDT_ENTRIES * core::mem::size_of::<Gate>() - 1) as u16;
        IDTP.base = addr_of_mut!(IDT) as u64;
        core::arch::asm!("lidt [rax]", in("rax") addr_of_mut!(IDTP) as *const IdtPtr, options(nostack));
    }
    serial::print(format_args!(
        "[mm] IDT live (256 gates, cs={:#x}, #PF probe-aware)\n",
        cs
    ));
    // Read-back verification (fail-fast): what the CPU ACTUALLY holds must
    // equal what we built. Catches any lidt/layout regression at boot.
    let mut idtr = [0u8; 10];
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack));
    }
    let lim = u16::from_le_bytes([idtr[0], idtr[1]]);
    let base = u64::from_le_bytes(idtr[2..10].try_into().unwrap());
    let (want_lim, want_base) = unsafe { (IDTP.limit, IDTP.base) };
    if lim != want_lim || base != want_base {
        panic_str_packed("IDTR readback mismatch");
    }
    serial::print(format_args!(
        "[mm] IDTR readback OK: base={:#x} limit={:#x}\n",
        base, lim
    ));
}

#[cold]
fn panic_str_packed(msg: &str) -> ! {
    crate::panic_str("idt: ", msg)
}

// --- Safe probes -------------------------------------------------------------

/// Read a u64 through an MMU-guarded probe. Returns `None` on fault
/// (the redOS "Access Denied" event), `Some(v)` on success.
///
/// CEP: CEP-1 | Complete
/// Cost: success ~5 instructions; fault = one exception round-trip.
/// Fail: a fault that is NOT at `addr` halts (fail-fast — see handler).
/// Assumes: single task at a time, interrupts disabled (arm/fixup pair
///          is race-free under the Phase-2 scheduling model).
pub fn probe_read(addr: u64) -> Option<u64> {
    let mut val: u64 = 0;
    let fault: u64;
    unsafe {
        EXPECTED = addr;
        ARMED = 1;
        core::arch::asm!(
            "lea rdi, [rip + 7f]",       // fixup label address
            "mov [rsi], rdi",
            "xor eax, eax",              // fault flag = 0 (success path)
            "mov rdx, [rcx]",            // ← the probe
            "jmp 8f",
            "7:",                        // handler rewires RIP here (rax=1)
            "8:",
            lateout("rdi") _,            // scratch (M1: declared, not assumed)
            in("rsi") addr_of_mut!(FIXUP),
            out("rdx") val,
            in("rcx") addr,
            inout("rax") 0u64 => fault,
            options(nostack)
        );
        ARMED = 0;
        FIXUP = 0;
    }
    if fault == 1 {
        None
    } else {
        Some(val)
    }
}

/// Write-probe: attempt `*addr = v` under the same protocol. Returns
/// `true` when the write landed, `false` when the MMU denied it.
/// CEP: CEP-1 | Complete
/// Cost/Fail: see `probe_read` (same semantics, write side).
pub fn probe_write(addr: u64, v: u64) -> bool {
    let fault: u64;
    unsafe {
        EXPECTED = addr;
        ARMED = 1;
        core::arch::asm!(
            "lea rdi, [rip + 7f]",
            "mov [rsi], rdi",
            "xor eax, eax",
            "mov [rcx], rdx",            // ← the probe
            "jmp 8f",
            "7:",
            "8:",
            lateout("rdi") _,            // scratch (M1: declared, not assumed)
            in("rsi") addr_of_mut!(FIXUP),
            in("rcx") addr,
            in("rdx") v,
            inout("rax") 0u64 => fault,
            options(nostack)
        );
        ARMED = 0;
        FIXUP = 0;
    }
    fault == 0
}
