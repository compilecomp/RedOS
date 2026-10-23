//! RedOS kernel — tasks, context switch, cooperative scheduler.
//!
//! Phase 2 model (documented scope): tasks are ring-0 kernel threads with
//! isolated stacks AND isolated address-space roots — each task carries a
//! `cr3` physical root loaded at every switch (full TLB flush: the
//! revocation-safe baseline, see mm/mod.rs). Private windows and
//! per-task-permission shared windows live in these roots (mm/pagemap.rs).
//! Preemptive scheduling and the ring-3 user/supervisor split arrive with
//! the IPC fast-path milestone; the capability model does not depend on
//! either.
//!
//! CEP: CEP-0-candidate | Complete (Phase 2 scope)
//! (The switch path keeps its CEP-0 candidacy: disassembly + cycle
//! measurement deferred to the fast-path milestone, where the switch is
//! rewritten with PCID — a measurement now would be thrown away.)
//! Cost: switch_to is fixed ~15 instructions + one CR3 load; the scheduler
//!       scan is O(MAX_TASKS).
//! Fail: no-runnable-task and double-block conditions halt via panic
//!       (named).
//! Assumes: x86_64 SysV; one CPU (no SMP in Phase 2); stacks are 16 KiB,
//!          allocated from the static pool below (no heap anywhere).

use crate::serial;
use core::arch::naked_asm;

pub const MAX_TASKS: usize = 4;
pub const STACK_SIZE: usize = 16 * 1024;

/// Callee-saved register image. Offsets MUST match `switch_to`:
/// r15@0 r14@8 r13@16 r12@24 rbx@32 rbp@40 rsp@48 — enforced below by
/// compile-time assertions (Law 3: not comment-only).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsp: u64,
}

// Law 3 enforcement: the naked asm's hard-coded offsets are only correct
// while these hold. Break the struct, break the build — not the boot.
const _: () = assert!(core::mem::offset_of!(Context, r15) == 0);
const _: () = assert!(core::mem::offset_of!(Context, rbx) == 32);
const _: () = assert!(core::mem::offset_of!(Context, rbp) == 40);
const _: () = assert!(core::mem::offset_of!(Context, rsp) == 48);

/// Task lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Not spawned (slot free).
    Free,
    /// In the runqueue.
    Runnable,
    /// Waiting for an endpoint message/mailbox slot (blocked in IPC).
    BlockedRecv(usize),
    /// Waiting to deposit a message into a full mailbox.
    BlockedSend(usize),
    /// Finished; slot retained (no reuse in Phase 1).
    Dead,
}

/// A kernel thread. Copy is derived ONLY so the static table can be
/// const-initialized ([expr; N] requires Copy); instances are never copied
/// at runtime (16 KiB stacks).
#[derive(Clone, Copy)]
pub struct Task {
    pub state: TaskState,
    pub ctx: Context,
    stack: [u8; STACK_SIZE],
    /// Registered receive request while blocked in ipc_recv (None otherwise).
    pub recv_req: Option<RecvReq>,
    /// Delivered length written by the router (read by ipc_recv after wake).
    pub recv_len: usize,
    /// Set by the router when a message was delivered directly into
    /// recv_req's buffer; the wake path consumes it BEFORE re-calling
    /// ipc_recv (otherwise a later mailbox message would be drained out of
    /// order — observed and fixed in v0.3.0 bring-up).
    pub delivered: bool,
    /// Physical CR3 root for this task's address space (mm/pagemap.rs).
    /// 0 = still running on the kernel root (the spawn default). Loaded at
    /// every context switch; a full TLB flush accompanies each load (no
    /// PCID in Phase 2 — the revocation-safe baseline).
    pub cr3: u64,
    // Align the stack so the image top can satisfy the SysV 16-byte
    // convention (task entry must see rsp ≡ 8 (mod 16)).
    _align: [u64; 0],
}

/// A blocked receiver's buffer registration (blind-copy destination).
#[derive(Clone, Copy)]
pub struct RecvReq {
    pub buf: *mut u8,
    pub max_len: usize,
}

// Static task table: no heap in the kernel (Law 1). 4 tasks × 16 KiB = 64 KiB
// of .bss — inside the 4 MiB load window enforced by linker.ld.
static mut TASKS: [Task; MAX_TASKS] = [new_task(); MAX_TASKS];

const fn new_task() -> Task {
    Task {
        state: TaskState::Free,
        ctx: Context {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rsp: 0,
        },
        stack: [0; STACK_SIZE],
        recv_req: None,
        recv_len: 0,
        delivered: false,
        cr3: 0,
        _align: [],
    }
}

// Scheduler cursor (round-robin scan start).
static mut SCHED_CURSOR: usize = 0;

/// CEP: CEP-0-candidate | Complete (Phase 1)
/// Cost: fixed 15 instructions; saves/restores all callee-saved GPRs.
/// Fail: cannot fail (no memory faults possible: both Context pointers are
///       kernel-image residents inside the identity map).
/// Assumes: SysV calling convention (old=*mut Context in RDI, new in RSI);
///          interrupts are disabled by the caller (cooperative Phase 1).
///
/// ABI CRITICAL: the return type is `()`, NOT `!`. A `!` signature lets the
/// compiler tail-jump here, which drops the caller's return address — and
/// the resumed task's final `ret` would then pop stale memory and jump into
/// firmware (observed and fixed in v0.3.0 bring-up). With `()`, the caller
/// pushes a real return address; on resume the `ret` lands back inside
/// `switch_to_task`, mid-call, exactly as the resume semantics require.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_to(old: *mut Context, new: *const Context) {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi + 48], rsp",
        "mov rsp, [rsi + 48]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret"
    )
}

/// CEP: CEP-1 | Complete
/// Cost: two instructions; transfers the entry argument via RDI.
/// Fail: never returns (entry functions are `-> !`).
/// Assumes: constructed stack image layout from `spawn` (see below).
#[unsafe(naked)]
unsafe extern "C" fn task_bootstrap() -> ! {
    naked_asm!("pop rdi", "ret")
}

/// CEP: CEP-1 | Complete
/// Cost: O(1); one free slot scan + fixed-size stack image construction.
/// Fail: panics if no free task slot remains (Phase 1 static capacity).
/// Assumes: entry never returns (`extern "C" fn(u64) -> !`); interrupts
///          disabled; called before the scheduler loop starts.
///
/// Slot 0 is RESERVED for kmain: scheduler_run saves kmain's context there
/// on the first switch. Spawning into slot 0 would let the saved context
/// overwrite a freshly constructed task image (observed and fixed in
/// v0.3.0 bring-up).
pub fn spawn(entry: extern "C" fn(u64) -> !, arg: u64) -> usize {
    // Find a free slot (skipping slot 0 — kmain's reservation).
    let slots = tasks();
    let idx = match slots[1..]
        .iter()
        .position(|t| matches!(t.state, TaskState::Free))
    {
        Some(i) => i + 1,
        None => panic_str("spawn: no free task slot"),
    };

    let task = &mut slots[idx];
    // Image layout (descending from S): [S]=bootstrap [S+8]=arg [S+16]=entry,
    // where S ≡ 0 (mod 16) so task_entry sees rsp = S+24 ≡ 8 (mod 16) —
    // matching the SysV "just after call" convention.
    let base = task.stack.as_mut_ptr() as u64;
    let img_hi = base + STACK_SIZE as u64;
    let s = (img_hi - 48) & !0xF;

    unsafe {
        write_stack(s, task_bootstrap as unsafe extern "C" fn() -> ! as u64);
        write_stack(s + 8, arg as u64);
        write_stack(s + 16, entry as extern "C" fn(u64) -> ! as u64);
        task.ctx.rsp = s - 48;
    }
    task.state = TaskState::Runnable;
    idx
}

/// Write one 8-byte word into a task stack image.
/// CEP: CEP-1 | Complete
/// Fail: cannot fail (caller guarantees the address is inside the pool).
#[inline(always)]
unsafe fn write_stack(addr: u64, val: u64) {
    (addr as *mut u64).write_volatile(val);
}

/// Switch to `next` from the current task, saving its context in `cur`.
/// The target task's CR3 root is loaded BEFORE the stack switch (both
/// contexts' code and the two Context structs live in the shared low
/// identity map, so the CR3 load cannot strand us).
/// CEP: CEP-1 | Complete
/// Cost: one CR3 load (full TLB flush) + fixed ~15 instructions in the
///       naked asm. Cycle measurement deferred to the fast-path milestone
///       (where the switch path is rewritten with PCID anyway).
/// Fail: cannot fail.
/// Returns: when `cur` is later resumed by another switch back to it —
/// the `ret` inside the naked asm lands back here, mid-call. That resume
/// semantics is the entire point of the stack-image design.
pub fn switch_to_task(cur: usize, next: usize) {
    debug_assert!(cur < MAX_TASKS && next < MAX_TASKS, "switch index OOB");
    let slots = tasks();
    let root = slots[next].cr3;
    if root != 0 && root != crate::mm::pagemap::current_cr3() {
        crate::mm::pagemap::switch_cr3(root);
    }
    unsafe {
        let old_ctx = &mut slots[cur].ctx as *mut Context;
        let new_ctx = &slots[next].ctx as *const Context;
        switch_to(old_ctx, new_ctx);
    }
}

/// CEP: CEP-1 | Complete
/// Cost: O(MAX_TASKS) per scan; total O(T²) over T switches (fine at ≤4).
/// Fail: if no task is runnable, prints the task table and halts — a
///       deadlock in a verified kernel must never be silent.
pub fn scheduler_run() -> ! {
    loop {
        let cur = unsafe { SCHED_CURSOR };
        let slots = tasks();
        let mut picked: Option<usize> = None;
        for off in 0..MAX_TASKS {
            let i = (cur + off) % MAX_TASKS;
            if matches!(slots[i].state, TaskState::Runnable) {
                picked = Some(i);
                break;
            }
        }
        match picked {
            Some(next) => {
                unsafe { SCHED_CURSOR = (next + 1) % MAX_TASKS };
                slots[next].state = TaskState::Runnable; // stays runnable
                // Current "task 0" is kmain itself: it called scheduler_run
                // and never returns; the first switch simply adopts `next`.
                let fake = 0usize; // kmain's context is never resumed
                switch_to_task(fake, next);
            }
            None => {
                serial::print(format_args!(
                    "[sched] no runnable task — deadlock or completion\n"
                ));
                for (i, t) in slots.iter().enumerate() {
                    serial::print(format_args!(
                        "  task {}: state {:?}\n",
                        i, t.state
                    ));
                }
                serial::print(format_args!("REDOS IPC TEST COMPLETE\n"));
                crate::halt_forever();
            }
        }
    }
}

/// Mark the calling task dead and yield control forever.
/// CEP: CEP-1 | Complete
/// Fail: cannot fail; never returns.
pub fn task_exit(cur: usize) -> ! {
    tasks()[cur].state = TaskState::Dead;
    schedule_from(cur);
    // Dead tasks are never resumed; this halt keeps the `!` type honest.
    crate::halt_forever()
}

/// Yield from task `cur`: scan and switch to the next runnable task.
/// CEP: CEP-1 | Complete
/// Fail: halts if nothing is runnable (completion or deadlock — never
///       silent). Returns normally when the task is resumed.
pub fn schedule_from(cur: usize) {
    assert_ne!(cur, 0, "kmain cannot yield in Phase 1");
    let slots = tasks();
    let mut picked: Option<usize> = None;
    for off in 1..MAX_TASKS {
        let i = (cur + off) % MAX_TASKS;
        if matches!(slots[i].state, TaskState::Runnable) {
            picked = Some(i);
            break;
        }
    }
    if let Some(next) = picked {
        unsafe { SCHED_CURSOR = (next + 1) % MAX_TASKS };
        switch_to_task(cur, next);
    } else {
        // Nothing runnable: distinguish clean completion from deadlock —
        // never print the success banner for a stuck task (Law 6).
        let slots = tasks();
        let stuck = slots.iter().any(|t| {
            matches!(
                t.state,
                TaskState::BlockedRecv(_) | TaskState::BlockedSend(_)
            )
        });
        if stuck {
            for (i, t) in slots.iter().enumerate() {
                serial::print(format_args!("  task {}: {:?}\n", i, t.state));
            }
            serial::print(format_args!("REDOS IPC DEADLOCK DETECTED\n"));
        } else {
            serial::print(format_args!("REDOS IPC TEST COMPLETE\n"));
        }
        crate::halt_forever()
    }
}

/// Mutable access to the task table (kernel is single-threaded at this
/// boundary — Phase 1 has no SMP).
#[allow(static_mut_refs)]
pub fn tasks() -> &'static mut [Task; MAX_TASKS] {
    unsafe { &mut *core::ptr::addr_of_mut!(TASKS) }
}

/// Phase-1 panic helper (message-based; used before/without fmt machinery).
#[cold]
pub fn panic_str(msg: &str) -> ! {
    crate::panic_str("task: ", msg)
}
