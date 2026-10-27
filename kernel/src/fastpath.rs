//! RedOS kernel — the register-path IPC fast path (v0.8.0).
//!
//! The byte router (ipc.rs) is the Phase-1 mechanism: a 4 KiB staging
//! copy through kernel memory, a scheduler scan to wake the peer. The
//! fast path moves the rendezvous into registers:
//!
//! * **Send** (`sys_send`): the caller's five payload registers are
//!   copied opaquely into the receiver's saved syscall frame, the
//!   receiver is marked runnable, and the sender DIRECT-SWITCHES to it —
//!   no mailbox staging, no scheduler scan, no double context hop.
//! * **Recv** (`sys_recv`): blocks by parking the frame pointer in the
//!   task record; the delivering send fills the parked frame in place,
//!   so the resumed dispatch simply returns and `sysretq` hands the
//!   payload back to user code.
//!
//! **Blindness (the tenet, unchanged):** the router inspects nothing but
//! authority. The payload is a `[u64; 5]` moved from one frame to
//! another — this module never compares, hashes, or interprets a single
//! payload word. The round-trip verification in the boot scenario lives
//! in the USER PROGRAMS (srv verifies its own protocol constants; the
//! router has no reference to them).
//!
//! Wait queues are SEPARATE from the byte router's (`frecv_waiter` /
//! `fsend_waiter` / `fstaged` live in the same Endpoint record but are
//! never consulted by the byte path): a byte-receiver can never consume
//! a register message and vice versa, so the v0.3.0 delivered-flag
//! lesson holds per flavor without cross-coupling.
//!
//! CEP: CEP-0-candidate | Complete (the deliver+switch path is the
//!       100-cycle budget's subject: `make fastpath-audit` counts the
//!       instructions; proof/Fastpath.thy proves payload-blindness and
//!       the exactly-once delivery discipline)
//! Cost: delivery O(1) (five register writes); block paths add one
//!       schedule scan; direct switch = one switch_to (~15 instrs).
//! Fail: named error codes to the caller (SYS_ERR); no silent overwrite
//!       of a staged sender (the v0.3.0 class of bug is named here too).
//! Assumes: single CPU, interrupts disabled, called from the syscall
//!          dispatch (ring 0); the caller's frame is on its kernel stack.

use crate::cap;
use crate::serial;
use crate::syscall::SyscallFrame;
use crate::task::{tasks, TaskState};

/// The opaque register payload. Copy-only by construction; the router
/// moves it, never reads it.
#[derive(Clone, Copy)]
pub struct Regs5([u64; 5]);

/// Delivered-message counter (exactly-once evidence for the scenario
/// layer: one rendezvous must produce exactly one delivery).
static mut DELIVER_COUNT: usize = 0;

/// Delivery counter (audit evidence).
/// CEP: CEP-1 | Complete
/// Cost: one load. Fail: cannot fail.
#[allow(static_mut_refs)]
pub fn deliver_count() -> usize {
    unsafe { DELIVER_COUNT }
}

/// Resolve a capability slot to (endpoint index, rights) for the register
/// path. The slot must name a live Endpoint capability with the needed
/// right — identical authority semantics to the byte router.
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: Err for free slots, wrong kind, missing right (never silent).
fn resolve(me: usize, cap_slot: usize, need: u8) -> Result<usize, u64> {
    if cap_slot >= cap::MAX_CAPS {
        return Err(crate::syscall::SYS_ERR);
    }
    let table = cap::table_of(me);
    match table.slots[cap_slot].kind {
        cap::CapKind::Endpoint { ep, rights } => {
            if rights & need != need || ep >= crate::ipc::MAX_ENDPOINTS {
                return Err(crate::syscall::SYS_ERR);
            }
            Ok(ep)
        }
        _ => Err(crate::syscall::SYS_ERR),
    }
}

// --- Cold error loggers (kept OUT of the hot handlers: the serial
// -- formatting machinery must never inline into the 100-cycle path;
// -- fastpath-audit counts the handler bodies, so bloat here would be
// -- a build failure, not a review finding) -------------------------------

/// Named refusal: bad capability slot on send.
/// CEP: CEP-2 | Complete (cold path)
#[cold]
#[inline(never)]
fn log_bad_cap(me: usize, cap_slot: usize, send: bool) {
    serial::print(format_args!(
        "[fast] task {} {}: bad capability (slot {})\n",
        me,
        if send { "send" } else { "recv" },
        cap_slot
    ));
}

/// Named refusal: a second staged sender / receiver on one endpoint.
/// CEP: CEP-2 | Complete (cold path)
#[cold]
#[inline(never)]
fn log_busy(ep_idx: usize, what: &str) {
    serial::print(format_args!("[fast] endpoint {}: {}\n", ep_idx, what));
}

/// The blind copy: five words move into the frame, zero words are read.
/// CEP: CEP-0-candidate | Complete
/// Cost: five stores.
/// Fail: cannot fail (the frame pointer is kernel-stack resident).
#[inline]
fn deliver_into(frame: *mut SyscallFrame, p: Regs5) {
    let f = unsafe { &mut *frame };
    f.rdi = p.0[0];
    f.rsi = p.0[1];
    f.rdx = p.0[2];
    f.r8 = p.0[3];
    f.r9 = p.0[4];
    f.rax = 0; // delivered
    unsafe { DELIVER_COUNT += 1 };
}

/// Deposit into a parked fast-receiver's frame and make it runnable.
/// CEP: CEP-0-candidate | Complete
/// Cost: five stores + O(1) state ops.
/// Fail: panics if the receiver has no parked frame (kernel bug — a
///       registered fast-receiver always has one; fail-fast like the
///       byte router's missing-recv_req panic).
fn deliver_fast(recv_task: usize, p: Regs5) {
    let ts = tasks();
    let frame_ptr = ts[recv_task].kframe;
    if frame_ptr == 0 {
        crate::panic_str("fastpath: ", "fast receiver woke without a parked frame");
    }
    ts[recv_task].kframe = 0;
    deliver_into(frame_ptr as *mut SyscallFrame, p);
    ts[recv_task].state = TaskState::Runnable;
}

/// SYS_IPC_SEND. `frame` is the SENDER's live frame (its rax is written
/// here because the direct switch leaves before the dispatch returns).
/// Returns the rax value for the dispatch to store (0 on every path that
/// reaches it).
///
/// Fast path: a fast-receiver parked on the endpoint → deliver into its
/// frame, mark it runnable, and DIRECT-SWITCH to the receiver (the
/// sender resumes mid-dispatch when the CPU comes back — the rendezvous
/// cost is one switch, not a scan plus a second hop).
/// Slow path: stage the registers, block the sender (one staged sender
/// per endpoint — a second is a named error, never a silent overwrite).
///
/// CEP: CEP-0-candidate | Complete
/// Cost: fast path O(1) + one switch; slow path O(1) + one schedule scan.
/// Fail: SYS_ERR for bad capability/rights/second-staged-sender (named in
///       the serial log; the caller's user code sees only the code).
#[no_mangle]
pub fn redos_fp_sys_send(
    me: usize,
    cap_slot: usize,
    payload: [u64; 5],
    frame: *mut SyscallFrame,
) -> u64 {
    let ep_idx = match resolve(me, cap_slot, cap::SEND) {
        Ok(ep) => ep,
        Err(code) => {
            log_bad_cap(me, cap_slot, true);
            return code;
        }
    };
    // --- Fast path: receiver parked? Deliver + direct switch. -------------
    // (The ONLY code between here and the switch — the block/error paths
    // live in the cold helpers so fastpath-audit's count stays honest.)
    let waiter = crate::ipc::endpoints()[ep_idx].frecv_waiter.take();
    if let Some(rt) = waiter {
        deliver_fast(rt, Regs5(payload));
        // Sender's rax: set BEFORE the switch (the dispatch's post-call
        // write never happens for the switching sender — we are gone by
        // then). Idempotent with the dispatch's `f.rax = result`.
        unsafe { (*frame).rax = 0 };
        crate::task::direct_switch(me, rt);
        return 0; // reached when the sender is later resumed
    }
    // --- Slow path: stage and block (out of line — scheduling fallback,
    // -- NOT part of the rendezvous budget; cost ≈ the byte router's).
    send_block(me, ep_idx, Regs5(payload), frame)
}

/// The send slow path (stage + block). Out of line: the rendezvous
/// budget counts the direct-delivery hop, not this scheduling fallback.
/// CEP: CEP-1 | Complete
/// Cost: O(1) + one schedule scan.
/// Fail: SYS_ERR when a second staged sender would be overwritten (named
///       — the v0.3.0 class of bug, named here too).
#[cold]
#[inline(never)]
fn send_block(me: usize, ep_idx: usize, p: Regs5, frame: *mut SyscallFrame) -> u64 {
    let eps = crate::ipc::endpoints();
    let ep = &mut eps[ep_idx];
    if ep.fstaged.is_some() || ep.fsend_waiter.is_some() {
        log_busy(
            ep_idx,
            "second register sender refused (staged sender would be overwritten)",
        );
        return crate::syscall::SYS_ERR;
    }
    ep.fstaged = Some(p);
    ep.fsend_waiter = Some(me);
    let ts = tasks();
    ts[me].state = TaskState::BlockedSendFast(ep_idx);
    unsafe { (*frame).rax = 0 }; // the staged send WILL succeed
    crate::task::schedule_from(me);
    0
}

/// SYS_IPC_RECV. The payload lands in the frame's rdi/rsi/rdx/r8/r9;
/// rax = 0 on delivery (written by the delivery paths below).
///
/// CEP: CEP-0-candidate | Complete
/// Cost: fast path O(1); block path O(1) + one schedule scan.
/// Fail: SYS_ERR for bad capability/rights/second-receiver (named).
#[no_mangle]
pub fn redos_fp_sys_recv(
    me: usize,
    cap_slot: usize,
    frame: *mut SyscallFrame,
) -> u64 {
    let ep_idx = match resolve(me, cap_slot, cap::RECV) {
        Ok(ep) => ep,
        Err(code) => {
            log_bad_cap(me, cap_slot, false);
            return code;
        }
    };

    // Staged message waiting (a sender blocked before we parked)?
    let staged = crate::ipc::endpoints()[ep_idx].fstaged.take();
    if let Some(p) = staged {
        let eps = crate::ipc::endpoints();
        // Wake the staged sender: its rax is already 0 (set at block
        // time); just mark it runnable.
        if let Some(st) = eps[ep_idx].fsend_waiter.take() {
            let ts = tasks();
            ts[st].state = TaskState::Runnable;
        }
        deliver_into(frame, p);
        return 0;
    }

    // Park and block (out of line — the scheduling fallback, not the
    // rendezvous budget's subject). On wake, deliver_fast has already
    // filled the frame; the resumed dispatch returns it verbatim.
    recv_park(me, ep_idx, frame)
}

/// The recv slow path (park the frame + block). Out of line for the
/// same reason as `send_block`.
/// CEP: CEP-1 | Complete
/// Cost: O(1) + one schedule scan.
/// Fail: SYS_ERR when a second receiver would overwrite the registration
///       (named — never silent).
#[cold]
#[inline(never)]
fn recv_park(me: usize, ep_idx: usize, frame: *mut SyscallFrame) -> u64 {
    {
        let eps = crate::ipc::endpoints();
        let ep = &mut eps[ep_idx];
        if ep.frecv_waiter.is_some() {
            log_busy(ep_idx, "second register receiver refused");
            return crate::syscall::SYS_ERR;
        }
        ep.frecv_waiter = Some(me);
    }
    let ts = tasks();
    ts[me].kframe = frame as u64;
    ts[me].state = TaskState::BlockedRecvFast(ep_idx);
    crate::task::schedule_from(me);
    0 // resumed after delivery: frame already filled, rax already 0
}
