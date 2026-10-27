//! RedOS kernel — tasks, context switch, cooperative scheduler.
//!
//! Phase 2 model: tasks carry isolated stacks AND isolated address-space
//! roots — each task carries a `cr3` physical root loaded at every switch.
//! v0.8.0 adds the ring-3 user task: a task spawned with a user entry
//! (rip/rsp) runs through the `user_trampoline` (iretq into ring 3); its
//! kernel interactions are exclusively syscalls (syscall.rs). `CURRENT`
//! tracks the running slot for the fault-containment path, `EXIT_CODE`
//! records user exit statuses for the scenario layer, and `direct_switch`
//! is the rendezvous primitive behind the register fast path.
//!
//! CEP: CEP-0-candidate | Complete (switch_to is the measured switch; the
//!       PCID noflush load makes the CR3 reload ~free — see fastpath-audit)
//! Cost: switch_to is fixed ~15 instructions + one CR3 load; the scheduler
//!       scan is O(MAX_TASKS).
//! Fail: no-runnable-task and double-block conditions halt via panic
//!       (named).
//! Assumes: x86_64 SysV; one CPU (no SMP in Phase 2); stacks are 16 KiB,
//!          allocated from the static pool below (no heap anywhere).

use crate::serial;
use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MAX_TASKS: usize = 12;
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
    /// Parked in a register-path recv (frame pointer in `kframe`).
    BlockedRecvFast(usize),
    /// Blocked with registers staged (register path, no receiver yet).
    BlockedSendFast(usize),
    /// Finished; slot retained (no reuse in Phase 2).
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
    /// every context switch (PCID-tagged, noflush when the pair is live).
    pub cr3: u64,
    /// This root's PCID tag (0 = flush-mode load; pagemap.pcid_of is the
    /// authoritative map — this field is the per-task fast copy).
    pub pcid: u16,
    /// Parked syscall frame pointer while BlockedRecvFast (0 = none).
    /// Written by fastpath::sys_recv, consumed by deliver_fast.
    pub kframe: u64,
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

// Static task table: no heap in the kernel (Law 1). 6 tasks × 16 KiB = 96 KiB
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
        pcid: 0,
        kframe: 0,
        _align: [],
    }
}

// Scheduler cursor (round-robin scan start).
static mut SCHED_CURSOR: usize = 0;

/// The currently-running task slot (0 = kmain until the first switch).
/// Maintained by every switch path; the fault-containment handler reads
/// it to name and kill the faulting user task.
static mut CURRENT: usize = 0;

/// The current task slot.
/// CEP: CEP-1 | Complete
/// Cost: one load. Fail: cannot fail.
pub fn current() -> usize {
    unsafe { CURRENT }
}

/// Per-task user exit codes (SYS_EXIT writes; the scenario layer reads).
/// 0 = clean; nonzero = program-defined; the containment path records
/// EXIT_FAULT_MARKER for contained ring-3 faults.
pub static EXIT_CODE: [AtomicU64; MAX_TASKS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_TASKS]
};

/// The exit status recorded when a ring-3 task is killed by a contained
/// fault (bit-patterned so it cannot collide with a small program code).
pub const EXIT_FAULT_MARKER: u64 = 0xFA11_0000_0000_0001;

/// Record a task's exit code (SYS_EXIT / containment path).
/// CEP: CEP-1 | Complete
/// Cost: one store. Fail: cannot fail (index is kernel-internal).
pub fn record_exit(task: usize, code: u64) {
    EXIT_CODE[task].store(code, Ordering::Relaxed);
}

/// Monotone scheduler tick: one bump per context switch. This is the ONLY
/// clock the KMS vault gets (no timer interrupt exists in Phase 2 —
/// interrupts are disabled), which makes lease expiry deterministic and
/// provable: leases expire strictly in switch order (proof/Kms.thy).
/// 64-bit at ~10^6 switches/s: no wrap concern (2^64 switches).
static mut SCHED_TICKS: u64 = 0;

/// Current scheduler tick (monotone; one tick per context switch).
/// CEP: CEP-1 | Complete
/// Cost: one load.
/// Fail: cannot fail.
pub fn ticks() -> u64 {
    unsafe { SCHED_TICKS }
}

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
#[no_mangle] // stable symbol: fastpath-audit measures the switch by name
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
        "ret",
        // End marker: fastpath-audit measures the switch by label range
        // (naked-asm symbols carry no ELF size).
        ".globl redos_switch_to_end",
        "redos_switch_to_end:"
    )
}

/// Spawn a task whose entry lives at raw address `entry_addr` (the
/// identity-manifest spawner's interface: the manifest binds the entry
/// by CONTENT hash, the spawner passes the resolved address). Same stack
/// image and slot discipline as `spawn`.
/// CEP: CEP-1 | Complete
/// Cost / Fail / Assumes: as `spawn`; additionally the caller guarantees
///       the address is real kernel text (a bad address faults on first
///       schedule — the manifest hash check exists to make that impossible).
pub fn spawn_at(entry_addr: u64, arg: u64) -> usize {
    // Find a free slot (skipping slot 0 — kmain's reservation).
    let slots = tasks();
    let idx = match slots[1..]
        .iter()
        .position(|t| matches!(t.state, TaskState::Free))
    {
        Some(i) => i + 1,
        None => panic_str("spawn_at: no free task slot"),
    };

    let task = &mut slots[idx];
    let base = task.stack.as_mut_ptr() as u64;
    let img_hi = base + STACK_SIZE as u64;
    let s = (img_hi - 48) & !0xF;

    unsafe {
        write_stack(s, task_bootstrap as unsafe extern "C" fn() -> ! as u64);
        write_stack(s + 8, arg as u64);
        write_stack(s + 16, entry_addr);
        task.ctx.rsp = s - 48;
    }
    task.state = TaskState::Runnable;
    idx
}

/// Spawn a RING-3 user task: on first schedule, `user_trampoline` loads
/// this task's kernel-stack top into the syscall entry cell, then irets
/// into ring 3 at `rip` with `rsp` (the ELF loader's user stack) and the
/// capability slot in RDI (the program's single bootstrap argument — the
/// "argv" of a zero-ID program is its authority handle, minted by the
/// spawner before the task ever runs).
///
/// Stack image (ascending): [s]=trampoline [s+8]=kstack_top [s+16]=rip
/// [s+24]=rsp [s+32]=cap_arg, ctx.rsp = s-48 — same discipline as spawn.
/// The caller MUST have set task.cr3/pcid BEFORE the first switch (the
/// spawner does: identity.rs installs the ELF-loaded root).
/// CEP: CEP-1 | Complete
/// Cost: O(1) image construction.
/// Fail: panics if no free slot remains (named static capacity limit).
/// Assumes: user windows already mapped in the task's root (elf.rs);
///          GDT/TSS/syscall MSRs live (gdt.rs/syscall.rs).
#[allow(dead_code)] // audit API: the scenario spawns via spawn_user_in (slot-scoped)
pub fn spawn_user(rip: u64, rsp: u64, cap_arg: u64) -> usize {
    let idx = match free_slot() {
        Some(i) => i,
        None => panic_str("spawn_user: no free task slot"),
    };
    spawn_user_in(idx, rip, rsp, cap_arg)
}

/// The lowest free task slot (skipping slot 0 — kmain's reservation).
/// Exposed for the ELF spawner, which must resolve the slot BEFORE
/// loading (the user stack window is slot-scoped).
/// CEP: CEP-1 | Complete
/// Cost: O(MAX_TASKS) scan.
/// Fail: None when the table is full (named by the caller).
pub fn free_slot() -> Option<usize> {
    tasks()[1..]
        .iter()
        .position(|t| matches!(t.state, TaskState::Free))
        .map(|i| i + 1)
}

/// spawn_user with a pre-reserved slot (the ELF spawner resolves the
/// stack window from the slot index before loading the image). Marks the
/// slot Runnable on return; the caller installs cr3/pcid immediately
/// after (before the task is ever scheduled).
/// CEP: CEP-1 | Complete
/// Cost: O(1) image construction.
/// Fail: panics if the reserved slot is not Free (wiring contract).
pub fn spawn_user_in(idx: usize, rip: u64, rsp: u64, cap_arg: u64) -> usize {
    let slots = tasks();
    if !matches!(slots[idx].state, TaskState::Free) {
        panic_str("spawn_user_in: reserved slot is not Free");
    }
    let task = &mut slots[idx];
    let base = task.stack.as_mut_ptr() as u64;
    let img_hi = base + STACK_SIZE as u64;
    let kstack_top = img_hi; // 16 KiB-aligned: the syscall frame contract
    let s = (img_hi - 48) & !0xF;
    unsafe {
        write_stack(s, user_trampoline as unsafe extern "C" fn() -> ! as u64);
        write_stack(s + 8, kstack_top);
        write_stack(s + 16, rip);
        write_stack(s + 24, rsp);
        write_stack(s + 32, cap_arg);
        task.ctx.rsp = s - 48;
    }
    task.state = TaskState::Runnable;
    idx
}

/// Ring-3 entry trampoline (runs once per user task, on its kernel
/// stack, ring 0). Pops the spawn image, publishes the kernel-stack top
/// for the syscall entry stub, builds the iret frame (user SS/RSP/
/// RFLAGS/CS/RIP), and drops to ring 3. RFLAGS = 0x2 (IF=0: the no-
/// interrupt kernel contract holds in user mode too — STI is privileged
/// and faults to the containment path).
///
/// ABI CRITICAL: pops in image order (kstack_top, rip, rsp, cap_arg);
/// the cap arg moves RDI←RSI so the user program receives it in RDI.
/// CEP: CEP-0-candidate | Complete
/// Cost: ~10 instructions, once per user task.
/// Fail: a bad user CS/SS/stack faults immediately into containment
///       (named); the constants are GDT-verified at gdt::init.
/// Assumes: called via the switch_to resume path with the image on top.
#[unsafe(naked)]
unsafe extern "C" fn user_trampoline() -> ! {
    naked_asm!(
        "pop rdi",               // kstack top
        "pop rcx",               // user rip
        "pop rdx",               // user rsp
        "pop rsi",               // cap arg
        "mov [{kstk}], rdi",    // publish syscall-entry stack top
        "mov rdi, rsi",         // user entry arg: rdi = cap slot
        "push 0x23",            // ss = UDS|3
        "push rdx",             // user rsp
        "push 0x2",             // rflags (IF=0, reserved bit 1 set)
        "push 0x1b",            // cs = UCS|3
        "push rcx",             // user rip
        "iretq",
        kstk = sym crate::syscall::USR_KSTK
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
/// identity map, so the CR3 load cannot strand us). The load is
/// PCID-tagged noflush when the PCID/INVPCID pair is live (the measured
/// optimization; pagemap.invalidate_root keeps revocation airtight).
/// CEP: CEP-0-candidate | Complete
/// Cost: one CR3 load + fixed ~15 instructions in the naked asm.
/// Fail: cannot fail.
/// Returns: when `cur` is later resumed by another switch back to it —
/// the `ret` inside the naked asm lands back here, mid-call. That resume
/// semantics is the entire point of the stack-image design.
pub fn switch_to_task(cur: usize, next: usize) {
    debug_assert!(cur < MAX_TASKS && next < MAX_TASKS, "switch index OOB");
    unsafe { SCHED_TICKS += 1; }
    let slots = tasks();
    let root = slots[next].cr3;
    if root != 0 && root != crate::mm::pagemap::current_cr3() {
        crate::mm::pagemap::switch_cr3_pcid(root, slots[next].pcid, true);
    }
    unsafe { CURRENT = next; }
    unsafe {
        let old_ctx = &mut slots[cur].ctx as *mut Context;
        let new_ctx = &slots[next].ctx as *const Context;
        switch_to(old_ctx, new_ctx);
    }
}

/// The rendezvous switch: transfer the CPU from `cur` DIRECTLY to `next`
/// (the register fast path's delivery hop — no scheduler scan). Same
/// mechanics as switch_to_task; a named wrapper so the fast path's cost
/// is auditable as a unit (fastpath-audit counts it separately).
/// CEP: CEP-0-candidate | Complete
/// Cost: one CR3 load (PCID noflush) + switch_to's ~15 instructions.
/// Fail: cannot fail.
pub fn direct_switch(cur: usize, next: usize) {
    switch_to_task(cur, next);
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

/// Cooperative tick-yield: hand the CPU to the next runnable task,
/// bumping the scheduler tick (the ONLY clock the KMS vault gets — see
/// kms.rs and proof/Kms.thy).
///
/// FAIRNESS (v0.7.0 bring-up lesson): the scan starts at cur+1 and only
/// falls back to a self-switch when the caller is the ONLY runnable
/// task. The v0.6.0 semantics (scan from cur) always re-picked the
/// caller, which starved every task woken while the caller kept
/// yielding — observed when the identity service (spawned Runnable) was
/// never scheduled because the vault client's input-wait yields kept
/// self-picking. The self-switch fallback preserves the lease clock
/// (ticks still bump when nothing else is runnable) without the halt
/// that `schedule_from` would take.
///
/// CEP: CEP-1 | Complete
/// Cost: one context switch (or a self-switch: same cost class).
/// Fail: cannot fail (the caller is Runnable by definition; the fallback
///       guarantees a target).
/// Assumes: called from a Runnable task; cooperative single-CPU.
pub fn yield_tick(cur: usize) {
    let slots = tasks();
    let mut picked: Option<usize> = None;
    for off in 1..MAX_TASKS {
        let i = (cur + off) % MAX_TASKS;
        if matches!(slots[i].state, TaskState::Runnable) {
            picked = Some(i);
            break;
        }
    }
    if picked.is_none() {
        // Self-switch fallback: caller is the only runnable task. Same
        // context saved and restored (a no-op switch that bumps the tick).
        picked = Some(cur);
    }
    if let Some(next) = picked {
        unsafe { SCHED_CURSOR = (next + 1) % MAX_TASKS };
        switch_to_task(cur, next);
    } else {
        // Unreachable: the fallback always produces a target.
        crate::halt_forever()
    }
}

/// Mark the calling task dead and yield control forever.
/// Session death (v0.7.0): the dead task's capability table is cleared and
/// every live Permission-Tracker grant is recorded Revoked — authority
/// cannot outlive its holder (mechanical, not conventional; Ident.thy).
/// CEP: CEP-1 | Complete
/// Fail: cannot fail; never returns.
pub fn task_exit(cur: usize) -> ! {
    tasks()[cur].state = TaskState::Dead;
    crate::identity::on_task_exit(cur);
    crate::cap::clear_table(cur);
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
                TaskState::BlockedRecv(_)
                    | TaskState::BlockedSend(_)
                    | TaskState::BlockedRecvFast(_)
                    | TaskState::BlockedSendFast(_)
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
