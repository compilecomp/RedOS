//! RedOS kernel — `syscall`/`sysret` ring transition and the register
//! fast path's entry substrate (v0.8.0).
//!
//! The ring boundary is crossed exactly twice per IPC hop:
//!
//! * **In** (user → kernel): the `syscall` instruction loads CS:SS from
//!   IA32_STAR, RFLAGS from RFLAGS & ~IA32_FMASK, jumps to IA32_LSTAR with
//!   the return RIP in RCX and the old RFLAGS in R11. The entry stub below
//!   switches to the current task's kernel stack (USR_KSTK, refreshed on
//!   every exit — a resumed task's stack top must not be read from a
//!   stale cell) and saves the full syscall frame.
//! * **Out** (kernel → user): `sysretq` restores RCX→RIP and R11→RFLAGS.
//!   The exit stub pops the frame the Rust dispatch returned a pointer to,
//!   so a task resumed mid-dispatch exits through the same code as a task
//!   that never blocked.
//!
//! Frame contract (ABI-critical, enforced by compile-time asserts below):
//! 16 pushes from the 16-byte-aligned kernel stack top — pad, rax, rdi,
//! rsi, rdx, rcx, r8, r9, r10, r11, rbx, rbp, r12, r13, r14, r15 — so the
//! `call` sees rsp ≡ 0 (mod 16) per SysV, and `dispatch` returns the frame
//! base in RAX for the symmetric pop sequence.
//!
//! Blindness note (the fast path's core tenet): the ROUTER (fastpath.rs)
//! copies payload registers opaquely. This module reads ONLY frame.rax
//! (the syscall number — a kernel ABI field, not message content) and
//! frame.r10 (the capability slot — authority, not content). The test
//! payload values live in the user programs, not here.
//!
//! CEP: CEP-0-candidate | Complete (instruction budget audited by
//!       `make fastpath-audit`: entry stub + dispatch + exit stub must
//!       stay inside the documented 100-cycle-per-hop budget envelope)
//! Cost: entry 17 instrs + dispatch + exit 18 instrs (see fastpath-audit).
//! Fail: unknown syscall numbers return a named error code to the CALLER
//!       (u64::MAX) — the kernel never guesses. Ring-0 bugs on the syscall
//!       stack still halt via the #PF path (cs&3 == 0 → fail-fast).
//! Assumes: GDT/TSS live (gdt.rs — STAR names OUR selectors); interrupts
//!          disabled; single CPU (USR_KSTK is a single cell, refreshed on
//!          every exit and at every trampoline entry).

use crate::serial;
use core::arch::global_asm;
use core::ptr::addr_of_mut;

// --- Syscall numbers (the user ABI; usr/sys.h mirrors these) -----------------

/// Echo service: returns arg1 ^ MAGIC. The kernel READS the argument by
/// design (it is the service's parameter) — this syscall is NOT payload
/// routing and is outside the blindness contract (documented in
/// proof/Fastpath.thy's model: `blind` covers the IPC commands only).
pub const SYS_PING: u64 = 0;
/// Exit: rdi = exit code, recorded for the scenario layer, task killed.
pub const SYS_EXIT: u64 = 1;
/// Register-path send: r10 = capability slot; payload = rdi,rsi,rdx,r8,r9.
pub const SYS_IPC_SEND: u64 = 2;
/// Register-path receive: r10 = capability slot; payload arrives in
/// rdi,rsi,rdx,r8,r9; rax = 0 on delivery.
pub const SYS_IPC_RECV: u64 = 3;

/// Generic error returned in rax for contract violations (named in the
/// serial log; the user program sees only the code — by design: no error
/// detail leaks across the ring boundary).
pub const SYS_ERR: u64 = u64::MAX;

/// PING's transform — public, constant, documented (an obfuscation-free
/// echo: the value proves the round trip happened, nothing more).
pub const PING_XOR: u64 = 0x5A5A_5A5A_5A5A_5A5A;

// --- The frame ---------------------------------------------------------------

/// The saved register image (see module docs for the layout contract).
/// `user_rsp` is the CRITICAL field: SYSRET restores RIP (RCX) and
/// RFLAGS (R11) but NOT RSP — the kernel switched stacks on entry, so
/// the user's stack pointer exists ONLY here. (Observed in v0.8.0
/// bring-up: a program that touched its stack between syscalls faulted
/// on a kernel address — its RSP was the kernel stack top.)
#[repr(C)]
pub struct SyscallFrame {
    /// Alignment pads (18 pushes ⇒ the `call` is 16-byte aligned).
    pub pad2: u64,
    pub pad1: u64,
    /// Callee-saved chain (offsets asserted below).
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    /// User RFLAGS (hardware-stashed by the syscall instruction).
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    /// User RIP (hardware-stashed by the syscall instruction).
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    /// Syscall number on entry; return value on exit.
    pub rax: u64,
    /// The user's stack pointer — restored by the exit stub's final
    /// `pop rsp` (SYSRET does not touch RSP).
    pub user_rsp: u64,
}

// Law 3: the naked asm's offsets are only correct while this holds.
const _: () = assert!(core::mem::size_of::<SyscallFrame>() == 144);
const _: () = assert!(core::mem::offset_of!(SyscallFrame, r15) == 16);
const _: () = assert!(core::mem::offset_of!(SyscallFrame, r11) == 64);
const _: () = assert!(core::mem::offset_of!(SyscallFrame, rcx) == 96);
const _: () = assert!(core::mem::offset_of!(SyscallFrame, rax) == 128);
const _: () = assert!(core::mem::offset_of!(SyscallFrame, user_rsp) == 136);

/// The kernel stack top of the CURRENTLY-entered user task. Refreshed by
/// (a) the trampoline before the first iretq into ring 3 and (b) every
/// exit stub (a task resumed mid-dispatch must not inherit another
/// task's cell value). Single cell: one CPU.
pub static mut USR_KSTK: u64 = 0;

/// Transient stash for the user's RSP between "still on the user stack"
/// and "pushed into the frame" (two instructions; single cell is safe:
/// no task switch can happen between them — the entry stub runs with
/// interrupts disabled by SFMASK and executes straight through).
static mut USR_RSP_CELL: u64 = 0;

// --- Entry/exit stubs ---------------------------------------------------------

global_asm!(
    ".section .text",
    ".globl redos_syscall_entry",
    "redos_syscall_entry:",
    // Stash the user RSP BEFORE the stack switch (SYSRET will not
    // restore it — the frame must carry it; see SyscallFrame docs).
    "    mov [{urcell}], rsp",
    "    mov rsp, [{kstk}]",          // this task's kernel stack top (16-aligned)
    "    push qword ptr [{urcell}]",  // user_rsp (first push: +136 in frame)
    "    push rax",                   // syscall number
    "    push rdi",
    "    push rsi",
    "    push rdx",
    "    push rcx",                   // user rip
    "    push r8",
    "    push r9",
    "    push r10",                   // capability slot
    "    push r11",                   // user rflags
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    push 0",                     // pad1 (frame alignment)
    "    push 0",                     // pad2
    "    mov rdi, rsp",
    "    call {dispatch}",
    "    mov rsp, rax",               // dispatch returns the frame base
    "    lea rcx, [rsp + 144]",
    "    mov [{kstk}], rcx",          // refresh USR_KSTK (this task's stack top)
    "    add rsp, 16",                // skip pad2/pad1 → r15 slot
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rcx",
    "    pop rdx",
    "    pop rsi",
    "    pop rdi",
    "    pop rax",
    "    pop rsp",                    // restore the USER stack pointer
    "    sysretq",
    // End-of-stub marker: the fastpath-audit target counts the stub by
    // symbol range, not by "next symbol" (the linker interleaves).
    ".globl redos_syscall_end",
    "redos_syscall_end:",
    kstk = sym USR_KSTK,
    urcell = sym USR_RSP_CELL,
    dispatch = sym redos_syscall_dispatch,
);

/// The Rust dispatch: reads the syscall number, runs the handler, returns
/// the frame pointer for the exit stub (never None — EXIT kills the task
/// inside the match arm and never reaches the return).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) per syscall (number dispatch + handler).
/// Fail: unknown numbers set rax = SYS_ERR (named in serial log at DEBUG
///       silence: the user program's contract, not a kernel fault).
/// Assumes: called from the entry stub with interrupts disabled.
#[no_mangle]
pub extern "C" fn redos_syscall_dispatch(frame: *mut SyscallFrame) -> *mut SyscallFrame {
    let f = unsafe { &mut *frame };
    let cur = crate::task::current();
    match f.rax {
        SYS_PING => {
            // Echo service: parameter in, transform out (not payload
            // routing — see the blindness note in the module docs).
            f.rax = f.rdi ^ PING_XOR;
        }
        SYS_EXIT => {
            let code = f.rdi;
            crate::task::record_exit(cur, code);
            crate::task::task_exit(cur); // never returns
        }
        SYS_IPC_SEND => {
            f.rax = crate::fastpath::redos_fp_sys_send(
                cur,
                f.r10 as usize,
                [f.rdi, f.rsi, f.rdx, f.r8, f.r9],
                frame,
            );
        }
        SYS_IPC_RECV => {
            f.rax = crate::fastpath::redos_fp_sys_recv(cur, f.r10 as usize, frame);
        }
        _ => {
            serial::print(format_args!(
                "[sys] task {} unknown syscall {} (SYS_ERR returned)\n",
                cur, f.rax
            ));
            f.rax = SYS_ERR;
        }
    }
    frame
}

// --- MSR/CR setup -------------------------------------------------------------

const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;

const EFER_SCE: u64 = 1 << 0;
const EFER_NXE: u64 = 1 << 11;

/// SFMASK clears these RFLAGS bits on entry: TF (single-step can never
/// trace the kernel), IF (kernel runs with interrupts disabled), DF (the
/// SysV direction contract), IOPL+NT (privilege hygiene), AC (alignment
/// checks are a user-mode debugging facility, not kernel policy).
const SFMASK_VAL: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 18);

fn rdmsr(msr: u32) -> u64 {
    let (hi, lo): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("edx") hi, out("eax") lo,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

fn wrmsr(msr: u32, val: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("edx") (val >> 32) as u32,
            in("eax") val as u32,
            options(nostack)
        );
    }
}

/// Program the syscall MSRs: EFER.SCE + NXE, STAR (kernel + user
/// selectors), LSTAR (entry), SFMASK. Verify each MSR by read-back —
/// a silently dropped wrmsr would surface as #UD in ring 3, far from
/// the cause.
///
/// STAR layout: [47:32] = kernel CS 0x08 (SS = 0x10 implied); [63:48] =
/// 0x28 so SYSRET computes CS = (0x28-0x10)|3 = 0x1b and SS =
/// (0x28-0x08)|3 = 0x23 — exactly gdt.rs's user descriptors.
///
/// CEP: CEP-1 | Complete
/// Cost: one-time boot path; four MSR writes + read-backs.
/// Fail: panics on any read-back mismatch (named).
/// Assumes: gdt.rs init ran (selectors 0x08/0x10/0x18/0x20 exist);
///          called before any user task exists.
pub fn init() {
    // EFER: syscall enable + NX enable (pagemap PTE_NX becomes live).
    let efer = rdmsr(MSR_EFER);
    wrmsr(MSR_EFER, efer | EFER_SCE | EFER_NXE);
    let efer_back = rdmsr(MSR_EFER);
    if efer_back & (EFER_SCE | EFER_NXE) != EFER_SCE | EFER_NXE {
        panic_str("EFER readback mismatch (SCE/NXE)");
    }

    let star = ((0x28u64) << 48) | ((crate::gdt::KCS as u64) << 32);
    wrmsr(MSR_STAR, star);
    if rdmsr(MSR_STAR) != star {
        panic_str("STAR readback mismatch");
    }

    let entry = redos_syscall_entry as *const () as u64;
    wrmsr(MSR_LSTAR, entry);
    if rdmsr(MSR_LSTAR) != entry {
        panic_str("LSTAR readback mismatch");
    }

    wrmsr(MSR_SFMASK, SFMASK_VAL);
    if rdmsr(MSR_SFMASK) != SFMASK_VAL {
        panic_str("SFMASK readback mismatch");
    }

    serial::print(format_args!(
        "[sys] syscall MSRs live: SCE+NXE, star={:#x} lstar={:#x} sfmask={:#x}\n",
        star, entry, SFMASK_VAL
    ));
}

// Extern reference to the entry stub (in the global_asm above).
#[allow(non_snake_case)]
extern "C" {
    fn redos_syscall_entry();
}

#[cold]
fn panic_str(reason: &str) -> ! {
    crate::panic_str("syscall: ", reason)
}

// Keep addr_of_mut referenced (the global_asm uses sym; this satisfies
// the linter that the static is "used" from Rust's perspective too).
#[allow(dead_code)]
fn _usr_kstk_addr() -> *mut u64 {
    addr_of_mut!(USR_KSTK)
}
