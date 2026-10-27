//! RedOS kernel — blind IPC router.
//!
//! Security property (this is the core tenet): the kernel checks ONLY the
//! message length and the sender's capability. It copies payload bytes
//! without ever inspecting them — payloads are ciphertext by convention and
//! the kernel must not care. This module is the implementation twin of
//! `proof/IPC.thy`: `route(out, in)` is proven independent of payload
//! content there.
//!
//! Model: bounded rendezvous mailbox (1 message per endpoint, 4 KiB max).
//! A sender with a full mailbox blocks; a receiver with an empty mailbox
//! blocks. Blocking tasks are woken by the counterpart operation. No
//! allocation, no locks (single-CPU cooperative Phase 1).
//!
//! CEP: CEP-1 | Complete (Phase 1; DMA-style zero-copy is Phase 3 with the
//!                   large-page FHE path)
//! Cost: send/recv O(MAX_MSG) — `stage()` zero-fills the 4 KiB Message
//!       record on every deposit (bounded, deterministic; a reusable
//!       zeroed-buffer scheme is a Phase 2 optimization).
//! Fail: named errors for bad capability/rights/length; internal state
//!       corruption halts via panic (fail-fast, never silent).
//! Assumes: single CPU, interrupts disabled (Phase 1); endpoints indexed by
//!          static table position (capability slot carries the index).

use crate::cap::{CTable, RECV, SEND};
use crate::task::{tasks, RecvReq, TaskState};

pub const MAX_ENDPOINTS: usize = 4;
pub const MAX_MSG: usize = 4096;

/// One pending message. Content is opaque to the kernel (blind routing).
#[derive(Clone, Copy)]
pub struct Message {
    pub len: usize,
    pub data: [u8; MAX_MSG],
}

/// IPC endpoint kernel object.
#[derive(Clone, Copy)]
pub struct Endpoint {
    /// Slot reserved (create_endpoint marks it; the emptiness of the
    /// mailbox alone is NOT a reservation — three creates would all
    /// collide on slot 0, observed in v0.7.0 bring-up).
    pub used: bool,
    /// Bounded mailbox (1 slot).
    pub pending: Option<Message>,
    /// True if a receiver task is blocked on this endpoint.
    pub recv_waiter: Option<usize>,
    /// True if a sender task is blocked (mailbox full).
    pub send_waiter: Option<usize>,
    /// Sender's staged message while blocked (mailbox full path).
    pub staged: Option<Message>,
    // --- Register-path queues (v0.8.0 fast path; SEPARATE from the byte
    // -- queues above — a byte receiver can never consume a register
    // -- message and vice versa; see fastpath.rs).
    /// A task parked in sys_recv (its frame pointer is in its Task).
    pub frecv_waiter: Option<usize>,
    /// A task blocked with registers staged (fast path, no receiver yet).
    pub fsend_waiter: Option<usize>,
    /// The staged register payload (opaque; the router never reads it).
    pub fstaged: Option<crate::fastpath::Regs5>,
}

const fn new_endpoint() -> Endpoint {
    Endpoint {
        used: false,
        pending: None,
        recv_waiter: None,
        send_waiter: None,
        staged: None,
        frecv_waiter: None,
        fsend_waiter: None,
        fstaged: None,
    }
}

static mut ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [new_endpoint(); MAX_ENDPOINTS];

/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: cannot fail (static capacity MAX_ENDPOINTS, checked by caller idx).
#[allow(static_mut_refs)]
pub fn endpoints() -> &'static mut [Endpoint; MAX_ENDPOINTS] {
    unsafe { &mut *core::ptr::addr_of_mut!(ENDPOINTS) }
}

/// CEP: CEP-1 | Complete
/// Cost: O(1). Creates an endpoint and returns its kernel index.
/// Fail: panics when all endpoint slots are used (named capacity limit).
///       The slot is RESERVED at create time (used flag): endpoint
///       identity is index-stable for the capability tokens that name it.
pub fn create_endpoint() -> usize {
    let eps = endpoints();
    match eps.iter().position(|e| !e.used) {
        Some(i) => {
            eps[i].used = true;
            i
        }
        None => crate::panic_str("ipc: ", "endpoint table full"),
    }
}

/// Validate that `task` holds a live capability for `ep` with `need` rights.
/// CEP: CEP-1 | Complete
/// Fail: Err with the reason (rights violations are never silent).
fn check_rights(table: &CTable, slot: usize, ep: usize, need: u8) -> Result<(), &'static str> {
    let rights = table.lookup_endpoint(slot, ep)?;
    if rights & need != need {
        return Err("capability lacks required rights");
    }
    Ok(())
}

/// CEP: CEP-1 | Complete
/// Cost: O(len) blind copy (len ≤ MAX_MSG enforced) + O(1) state ops.
/// Fail: named contract errors — bad cap, missing SEND right, zero-length,
///       oversize. NEVER fails on payload content (blind).
pub fn ipc_send(
    task_idx: usize,
    table: &mut CTable,
    cap_slot: usize,
    ep_idx: usize,
    data: &[u8],
) -> Result<(), IpcSendError> {
    if let Err(e) = check_rights(table, cap_slot, ep_idx, SEND) {
        return Err(IpcSendError::Contract(e));
    }
    if data.is_empty() || data.len() > MAX_MSG {
        return Err(IpcSendError::Contract(
            "message length out of contract (1..=MAX_MSG)",
        ));
    }

    let eps = endpoints();
    let ep = &mut eps[ep_idx];

    // Receiver already waiting? Deliver directly and wake it.
    if let Some(recv_task) = ep.recv_waiter.take() {
        deliver_to(ep, recv_task, data);
        return Ok(());
    }

    // Mailbox free? Deposit.
    if ep.pending.is_none() {
        ep.pending = Some(stage(data));
        return Ok(());
    }

    // Mailbox full: stage the message and block the sender. Phase 1
    // supports ONE blocked sender per endpoint — a second sender is a named
    // contract error, never a silent overwrite of the first waiter's staged
    // message (multi-waiter queues arrive with the Phase 2 scheduler).
    if ep.send_waiter.is_some() || ep.staged.is_some() {
        return Err(IpcSendError::Contract("endpoint already has a blocked sender"));
    }
    ep.staged = Some(stage(data));
    ep.send_waiter = Some(task_idx);
    let ts = tasks();
    ts[task_idx].state = TaskState::BlockedSend(ep_idx);
    Err(IpcSendError::Block)
}

pub enum IpcSendError {
    /// Named contract violation (no blocking happened).
    Contract(&'static str),
    /// Mailbox full: message staged, sender blocked; caller must yield.
    Block,
}

/// Copy `data` into a fresh message record (kernel-side staging buffer).
/// CEP: CEP-1 | Complete
fn stage(data: &[u8]) -> Message {
    let mut msg = Message {
        len: data.len(),
        data: [0u8; MAX_MSG],
    };
    msg.data[..data.len()].copy_from_slice(data);
    msg
}

/// Deliver `data` into `recv_task`'s registered receive request.
/// CEP: CEP-1 | Complete
/// Cost: O(len) blind copy.
/// Fail: panics if the receiver has no pending receive request (kernel bug —
///       a waiter is always registered before blocking). Fail-fast.
fn deliver_to(ep: &mut Endpoint, recv_task: usize, data: &[u8]) {
    // The receiver's request is stored in its task record by ipc_recv.
    let ts = tasks();
    match ts[recv_task].recv_req.take() {
        Some(req) => {
            let n = if data.len() < req.max_len {
                data.len()
            } else {
                req.max_len
            };
            // Blind copy: the kernel does not inspect a single byte.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), req.buf, n);
            }
            ts[recv_task].recv_len = n;
            ts[recv_task].delivered = true;
            ts[recv_task].state = TaskState::Runnable;
            // Clear the stale waiter marker on the endpoint (receiver woke).
            ep.recv_waiter = None;
        }
        None => crate::panic_str("ipc: ", "receiver woke without a registered request"),
    }
}

/// CEP: CEP-1 | Complete
/// Cost: O(len) blind copy + O(1) state ops.
/// Fail: bad cap / missing RECV right / oversize buffer contract. If a
///       message is not immediately available the task registers its
///       request and blocks (returns Err(IpcBlock); caller yields).
pub fn ipc_recv(
    task_idx: usize,
    table: &mut CTable,
    cap_slot: usize,
    ep_idx: usize,
    out_buf: *mut u8,
    max_len: usize,
) -> Result<usize, IpcRecvError> {
    if max_len == 0 || max_len > MAX_MSG {
        return Err(IpcRecvError::Contract(
            "receive buffer length out of contract (1..=MAX_MSG)",
        ));
    }
    if let Err(e) = check_rights(table, cap_slot, ep_idx, RECV) {
        return Err(IpcRecvError::Contract(e));
    }

    let eps = endpoints();
    let ep = &mut eps[ep_idx];

    // Message waiting in the mailbox? Drain it, wake any blocked sender.
    if let Some(msg) = ep.pending.take() {
        let n = copy_out(out_buf, max_len, &msg);
        wake_sender(ep);
        return Ok(n);
    }

    // Nothing pending: register the request and block. ONE blocked receiver
    // per endpoint in Phase 1 — a second receiver is a named contract error,
    // never a silent overwrite of the first waiter's registration.
    if ep.recv_waiter.is_some() {
        return Err(IpcRecvError::Contract(
            "endpoint already has a blocked receiver",
        ));
    }
    let ts = tasks();
    ts[task_idx].recv_req = Some(RecvReq {
        buf: out_buf,
        max_len,
    });
    ts[task_idx].state = TaskState::BlockedRecv(ep_idx);
    ep.recv_waiter = Some(task_idx);
    Err(IpcRecvError::Block)
}

pub enum IpcRecvError {
    /// Named contract violation (no blocking happened).
    Contract(&'static str),
    /// No message available: request registered, caller must yield.
    Block,
}

/// Copy at most `max_len` bytes of `msg` into `out`. Blind: content flows
/// untouched from sender to receiver through kernel memory.
/// CEP: CEP-1 | Complete
fn copy_out(out: *mut u8, max_len: usize, msg: &Message) -> usize {
    let n = if msg.len < max_len { msg.len } else { max_len };
    unsafe {
        core::ptr::copy_nonoverlapping(msg.data.as_ptr(), out, n);
    }
    n
}

/// If a sender is blocked on this endpoint, move its staged message into
/// the (now empty) mailbox and mark the sender runnable.
/// CEP: CEP-1 | Complete
fn wake_sender(ep: &mut Endpoint) {
    if let Some(send_task) = ep.send_waiter.take() {
        if let Some(staged) = ep.staged.take() {
            ep.pending = Some(staged);
            let ts = tasks();
            ts[send_task].state = TaskState::Runnable;
        }
    }
}
