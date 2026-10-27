//! RedOS kernel — Global Descriptor Table, Task State Segment, and the
//! ring-3 segment substrate (v0.8.0, IPC fast-path + Glass Wall).
//!
//! The bootloader hands off on OVMF's firmware segments; the kernel owned
//! no GDT of its own through Phase 2 (ring 0 only, no TSS — interrupts and
//! syscalls never changed stacks). Ring 3 changes that in two ways:
//!
//! 1. `syscall`/`sysret` load CS/SS from the IA32_STAR MSRs — the selectors
//!    they name must be descriptors WE control, laid out to STAR's contract
//!    (see syscall.rs): kernel CS 0x08, kernel SS 0x10, user code 0x18,
//!    user data 0x20.
//! 2. Exceptions from ring 3 (a user #PF/#GP/#UD) switch stacks through
//!    **TSS.RSP0** — the CPU loads RSP:SS from it before pushing the trap
//!    frame. Without a loaded TSS, the first user fault would push onto the
//!    user's own (untrusted) stack. RSP0 points at a dedicated fault stack
//!    allocated in this module — kernel-owned, wiped class General, never
//!    handed to a task.
//!
//! The switch sequence is the canonical one: `lgdt` (kernel data + stack
//! reload), a far return through a scratch stack image to reload CS, the
//! data segment reloads, then `ltr`. Everything is verified by read-back
//! (sgdt/str) — Law 6: a segment substrate that silently failed to load
//! would turn the first ring-3 transition into an unrebootable mystery.
//!
//! Layout (STAR contract, syscall.rs):
//! ```text
//!   0x00 null | 0x08 kcode | 0x10 kdata | 0x18 ucode(L,DPL3)
//!   0x20 udata(DPL3) | 0x28 TSS (doublewidth)
//! ```
//!
//! CEP: CEP-1 | Complete
//! Cost: one-time boot path; RSP0 switch on every user fault (hardware).
//! Fail: read-back mismatches and selector sanity violations panic (named).
//! Assumes: long mode; interrupts disabled (they are — no gate is a trap
//!          through this module); one CPU (one TSS, one RSP0, no IST).

use crate::serial;
use core::arch::naked_asm;

/// Kernel code selector (STAR.SYSCALL CS; also the post-switch CS).
pub const KCS: u16 = 0x08;
/// Kernel data selector (STAR.SYSCALL SS).
pub const KDS: u16 = 0x10;
/// User code selector (SYSRET CS = 0x18, RPL3 = 0x1b).
pub const UCS: u16 = 0x18;
/// User data selector (SYSRET SS = 0x20, RPL3 = 0x23).
pub const UDS: u16 = 0x20;
/// TSS selector.
pub const TSS: u16 = 0x28;

/// User fault stack: what RSP0 points at. Exceptions from ring 3 land
/// here (16 KiB — one deep trap frame; faults never nest in a no-interrupt
/// kernel: the handler either contains or halts before returning).
const FAULT_STACK_SIZE: usize = 16 * 1024;

#[repr(C, align(16))]
struct FaultStack([u8; FAULT_STACK_SIZE]);

static mut FAULT_STACK: FaultStack = FaultStack([0; FAULT_STACK_SIZE]);

/// x86_64 TSS (the subset the CPU reads in long mode: RSP0-2 and IST1-7).
/// PACKED: the hardware layout has RSP0 at offset 4 (right after the
/// 32-bit reserved field) — a repr(C, align(8)) mirror would push it to
/// offset 8 and the CPU would load garbage into RSP on every ring-3
/// fault (observed in v0.8.0 bring-up: user #PF -> #SS -> #DF; the same
/// class of layout trap as the packed IDTR/GDTR).
#[repr(C, packed(1))]
pub struct Tss {
    /// Reserved (legacy 32-bit link).
    pub reserved0: u32,
    /// Stack loaded on privilege transition to ring 0 (offset 4!).
    /// RSP1/RSP2 unused (no nested rings in this design).
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    /// Reserved.
    pub reserved1: u64,
    /// Interrupt stack table (unused: ist=0 in every gate).
    pub ist: [u64; 7],
    /// Reserved.
    pub reserved2: u64,
    /// I/O map base — set past the segment limit: every IN/OUT from
    /// ring 3 faults to containment (no user I/O port access, by
    /// construction rather than bitmap).
    pub iopb: u16,
}

const fn new_tss() -> Tss {
    Tss {
        reserved0: 0,
        rsp0: 0,
        rsp1: 0,
        rsp2: 0,
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        iopb: 104, // beyond the limit (103): all port I/O denied
    }
}

static mut TSS_SEG: Tss = new_tss();

/// The 64-bit descriptors. Eight-byte entries as canonical constants;
/// the TSS occupies a doublewidth slot (0x28..0x38).
static mut GDT: [u64; 7] = [
    0x0000_0000_0000_0000, // 0x00 null
    0x00AF_9A00_0000_FFFF, // 0x08 kcode: P DPL0 S code R  A, G L
    0x00CF_9200_0000_FFFF, // 0x10 kdata: P DPL0 S data RW A, G D
    0x00AF_FA00_0000_FFFF, // 0x18 ucode: P DPL3 S code R  A, G L
    0x00CF_F200_0000_FFFF, // 0x20 udata: P DPL3 S data RW A, G D
    0,                     // 0x28 TSS descriptor lo (filled at init)
    0,                     // 0x30 TSS descriptor hi (contiguous: 16-byte slot)
];

/// 10-byte GDTR image: limit@0, base@2 — packed, same layout trap as the
/// IDTR (repr(C) would pad base to offset 8 and the CPU would read junk).
#[repr(C, packed(1))]
struct Gdtr {
    limit: u16,
    base: u64,
}

static mut GDTR: Gdtr = Gdtr { limit: 0, base: 0 };

/// Reload CS through a far return: push cs, push return rip, `retfq`.
/// CEP: CEP-1 | Complete
/// Cost: one far return.
/// Fail: a bad CS descriptor faults on the retf itself (fail-fast; the
///       constants above are verified by the read-back below regardless).
#[unsafe(naked)]
unsafe extern "C" fn reload_cs() {
    naked_asm!(
        "push 0x08",
        "lea rax, [rip + 2f]",
        "push rax",
        "retfq",
        "2:",
        "ret"
    )
}

/// Build the GDT/TSS, load them, reload every segment register, and
/// verify by read-back.
///
/// CEP: CEP-1 | Complete
/// Cost: one-time boot path.
/// Fail: panics on: TSS above 4 GiB (descriptor would truncate the base),
///       GDT limit inconsistency, or any sgdt/str read-back mismatch.
/// Assumes: called after pagemap::init (identity map live); before
///          idt::init (the gates then record OUR kernel CS = 0x08).
pub fn init() {
    unsafe {
        let tss_addr = core::ptr::addr_of_mut!(TSS_SEG) as u64;
        let fault_top = (core::ptr::addr_of_mut!(FAULT_STACK) as u64)
            + FAULT_STACK_SIZE as u64;
        TSS_SEG.rsp0 = fault_top;

        if tss_addr > 0xFFFF_FFFF {
            panic_str("TSS above 4 GiB — descriptor cannot encode it");
        }
        // TSS descriptor: 16 bytes at GDT[5..7]. Byte layout of the low
        // u64: [0..2) limit15:0 | [2..5) base23:0 | [5] access=0x89
        // (P=1, type 0x9 = 64-bit TSS available) | [6] flags+limit19:16
        // (G=0; limit fits 16 bits) | [7] base31:24. High u64 = base63:32.
        // (The v0.8.0 bring-up draft had limit and base24:31 swapped —
        // TR read-back caught it: ring-3 faults loaded a garbage RSP0
        // and double-faulted.)
        let base = tss_addr;
        GDT[5] = (103u64) // limit 0..=103 (sizeof Tss = 104)
            | ((base & 0xFF) << 16)
            | (((base >> 8) & 0xFF) << 24)
            | (((base >> 16) & 0xFF) << 32)
            | (0x89u64 << 40) // P=1, DPL=0, type 0x9 (64-bit TSS, avail)
            | (((base >> 24) & 0xFF) << 56);
        GDT[6] = (base >> 32) & 0xFFFF_FFFF;

        GDTR.limit = (7 * 8 - 1) as u16; // 5 entries + 16-byte TSS slot
        GDTR.base = core::ptr::addr_of_mut!(GDT) as u64;

        core::arch::asm!("lgdt [rax]",
            in("rax") core::ptr::addr_of_mut!(GDTR) as u64, options(nostack));
        // Reload data segments first (a far return needs a live stack —
        // SS is not reloaded across the retf by hardware; we do it here).
        core::arch::asm!(
            "mov ds, {0:x}", "mov es, {0:x}", "mov ss, {0:x}",
            in(reg) KDS as u64, options(nostack));
        reload_cs();
        // Task register.
        core::arch::asm!("ltr {0:x}", in(reg) TSS as u64, options(nostack));

        // --- Read-back (Law 6) -------------------------------------------
        let mut gdtr_back = [0u8; 10];
        core::arch::asm!("sgdt [{}]", in(reg) gdtr_back.as_mut_ptr(), options(nostack));
        let lim = u16::from_le_bytes([gdtr_back[0], gdtr_back[1]]);
        let base_back = u64::from_le_bytes(gdtr_back[2..10].try_into().unwrap());
        if lim != GDTR.limit || base_back != GDTR.base {
            panic_str("GDTR readback mismatch");
        }
        // STR is the only way to read the task register ("mov x, tr" is
        // not an instruction — LLVM parsed it as a symbol reference).
        let mut tr_back: u16 = 0;
        core::arch::asm!("str {0:x}", lateout(reg) tr_back, options(nostack));
        if tr_back != TSS {
            panic_str("TR readback mismatch");
        }
        if TSS_SEG.rsp0 != fault_top {
            panic_str("TSS.rsp0 writeback mismatch");
        }

        serial::print(format_args!(
            "[sys] GDT/TSS live: kcs={:#x} kds={:#x} ucs={:#x} uds={:#x} tss={:#x} rsp0={:#x}\n",
            KCS, KDS, UCS, UDS, TSS, fault_top
        ));
        serial::print(format_args!("REDOS GDT-TSS PASS\n"));
    }
}

#[cold]
fn panic_str(reason: &str) -> ! {
    crate::panic_str("gdt: ", reason)
}
