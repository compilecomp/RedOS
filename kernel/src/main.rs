//! RedOS kernel — entry point (Phase 1, push 3 of 4).
//!
//! v0.3.0 scope: capability manager + blind IPC router + two kernel threads
//! running the Phase 1 milestone: Task A encrypts a message with AES-256-GCM
//! (C core), the kernel routes the ciphertext blindly, Task B decrypts and
//! verifies it. Both a clean pass and a tamper-rejection path are exercised.
//!
//! CEP: CEP-1 | Complete (v0.3.0 scope)
//! Cost: cold boot path + the two test tasks; all output via polled UART.
//! Fail: panics (named, serial) on any handoff/IPC/crypto contract breach;
//!       the test reports PASS/FAIL lines verbatim for the CI boot test.
//! Assumes: identity mapping + handoff from the Zig bootloader; interrupts
//!          disabled; cooperative scheduling (see task.rs scope note).

#![no_std]
#![no_main]
#![deny(missing_docs)]

mod cap;
mod ffi;
mod handoff;
mod ipc;
mod serial;
mod task;

use cap::{CTable, RW};
use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use ffi::{gcm_decrypt, gcm_encrypt, IV_LEN, KEY_LEN, TAG_LEN};
use handoff::{Handoff, MEM_RESERVED, MEM_USABLE};
use ipc::IpcSendError;

/// Phase-1 test key. Phase 2 replaces this with the RAM-only KMS vault
/// (Argon2id-derived, mlocked, wiped on power loss). Until then the key is
/// a compile-time constant — acceptable ONLY because Phase 1 has no
/// persistent storage and no external interfaces (documented decision).
const TEST_KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const TEST_IV: [u8; IV_LEN] = [0x07; IV_LEN];
const PLAINTEXT: &[u8] = b"SOVEREIGN-HELLO-FROM-REDOS-PHASE1";

/// Task table indices assigned by kmain at spawn time. Atomics because the
/// compiler must not assume aliasing freedom across the context-switch asm
/// boundary; values are written once by kmain before any task runs.
static TASK_A: AtomicUsize = AtomicUsize::new(0);
static TASK_B: AtomicUsize = AtomicUsize::new(0);

/// Per-task capability tables (minted by kmain, mutated only by kmain at
/// spawn; tasks use them read-only — Phase 1 has no user-mode faults).
static mut TABLE_A: CTable = CTable::new();
static mut TABLE_B: CTable = CTable::new();

/// Endpoint index created by kmain (write-once; see TASK_A note).
static EP: AtomicUsize = AtomicUsize::new(0);
/// Capability slot indices minted per task (write-once).
static CAP_A: AtomicUsize = AtomicUsize::new(0);
static CAP_B: AtomicUsize = AtomicUsize::new(0);

/// CEP: CEP-1 | Complete
/// Cost: one-time boot path.
/// Fail: panics on invalid handoff (named reason printed first).
/// Assumes: called by the bootloader exactly once, RDI = &Handoff (SysV).
#[no_mangle]
pub extern "C" fn _start(boot: &Handoff) -> ! {
    serial::init();

    serial::print(format_args!("\n=== RedOS v0.3.0 kernel ===\n"));

    if let Err(reason) = boot.validate() {
        panic_str("handoff rejected: ", reason);
    }
    serial::print(format_args!("[boot] handoff OK (version {})\n", boot.version));
    report_memory_map(boot);

    // Self-test the crypto core before trusting it with the milestone.
    if let Err(e) = crypto_selftest() {
        panic_str("crypto selftest failed: ", e);
    }
    serial::print(format_args!("[boot] crypto core selftest OK\n"));

    // --- Phase 1 milestone wiring -----------------------------------------
    let ep = ipc::create_endpoint();
    EP.store(ep, Ordering::Relaxed);
    let cap_a = table_a()
        .mint(ep, RW)
        .unwrap_or_else(|e| panic_str("mint A: ", e));
    let cap_b = table_b()
        .mint(ep, RW)
        .unwrap_or_else(|e| panic_str("mint B: ", e));
    CAP_A.store(cap_a, Ordering::Relaxed);
    CAP_B.store(cap_b, Ordering::Relaxed);
    serial::print(format_args!(
        "[boot] endpoint {} minted; caps A={} B={}\n",
        ep, cap_a, cap_b
    ));

    // Spawn B first: it blocks on recv so the mailbox rendezvous is
    // exercised deterministically (send-wake path, then block-wake path).
    let b = task::spawn(echo_b, 0);
    TASK_B.store(b, Ordering::Relaxed);
    let a = task::spawn(echo_a, 0);
    TASK_A.store(a, Ordering::Relaxed);
    serial::print(format_args!("[boot] tasks spawned: A={} B={}\n", a, b));

    task::scheduler_run()
}

/// Task A: encrypt two messages, send both through the blind router.
/// Message 2 carries a flipped ciphertext bit to exercise the tamper path.
/// CEP: CEP-1 | Complete
/// Fail: panics on any crypto/IPC contract breach (fail-fast).
extern "C" fn echo_a(_arg: u64) -> ! {
    let me = TASK_A.load(Ordering::Relaxed);
    let ep = EP.load(Ordering::Relaxed);
    let cap = CAP_A.load(Ordering::Relaxed);

    // Message 1: clean ciphertext.
    let ct1 = ct_buffer_a();
    let mut tag1 = [0u8; TAG_LEN];
    match gcm_encrypt(&TEST_KEY, &TEST_IV, PLAINTEXT, &[], ct1, &mut tag1) {
        Ok(()) => {}
        Err(e) => panic_str("A: encrypt m1: ", e),
    }
    let wire = wire_buffer_a();
    let n1 = PLAINTEXT.len();
    wire[..n1].copy_from_slice(&ct1[..n1]);
    wire[n1..n1 + TAG_LEN].copy_from_slice(&tag1);
    serial::print(format_args!("[A] sending {} ciphertext bytes\n", n1 + TAG_LEN));

    match ipc::ipc_send(me, table_a(), cap, ep, &wire[..n1 + TAG_LEN]) {
        Ok(()) => {}
        Err(IpcSendError::Block) => task::schedule_from(me),
        Err(IpcSendError::Contract(e)) => panic_str("A: send m1: ", e),
    }

    // Message 2: single flipped bit in the ciphertext (tag now invalid).
    let ct2 = ct_buffer_a2();
    let mut tag2 = [0u8; TAG_LEN];
    if let Err(e) = gcm_encrypt(&TEST_KEY, &TEST_IV, PLAINTEXT, &[], ct2, &mut tag2) {
        panic_str("A: encrypt m2: ", e);
    }
    ct2[3] ^= 0x10;
    wire[..n1].copy_from_slice(&ct2[..n1]);
    wire[n1..n1 + TAG_LEN].copy_from_slice(&tag2);
    serial::print(format_args!("[A] sending tampered message\n"));

    match ipc::ipc_send(me, table_a(), cap, ep, &wire[..n1 + TAG_LEN]) {
        Ok(()) => {}
        Err(IpcSendError::Block) => task::schedule_from(me),
        Err(IpcSendError::Contract(e)) => panic_str("A: send m2: ", e),
    }

    serial::print(format_args!("[A] done\n"));
    task::task_exit(me)
}

/// Task B: receive both messages; verify clean pass + tamper rejection.
/// CEP: CEP-1 | Complete
/// Fail: FAIL lines (not panic) so the CI log records the failed assertion.
extern "C" fn echo_b(_arg: u64) -> ! {
    let me = TASK_B.load(Ordering::Relaxed);
    let ep = EP.load(Ordering::Relaxed);
    let cap = CAP_B.load(Ordering::Relaxed);
    let n = PLAINTEXT.len();

    // --- Message 1: must authenticate and round-trip -----------------------
    let mut buf = recv_buffer_b();
    let got = match ipc_recv_blocking(me, cap, ep, &mut buf) {
        Some(g) => g,
        None => task::task_exit(me),
    };
    if got != n + TAG_LEN {
        serial::print(format_args!(
            "[B] FAIL: got {} bytes, want {}\n",
            got,
            n + TAG_LEN
        ));
        task::task_exit(me);
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[n..n + TAG_LEN]);
    let mut pt = [0u8; ipc::MAX_MSG];
    match gcm_decrypt(&TEST_KEY, &TEST_IV, &buf[..n], &[], &mut tag, &mut pt[..n]) {
        Ok(()) => {
            if &pt[..n] == PLAINTEXT {
                serial::print(format_args!(
                    "[B] decrypted: {}\n",
                    core::str::from_utf8(&pt[..n]).unwrap_or("<invalid utf8>")
                ));
                serial::print(format_args!("REDOS IPC TEST PASS\n"));
            } else {
                serial::print(format_args!("[B] FAIL: plaintext mismatch\n"));
            }
        }
        Err(e) => serial::print(format_args!("[B] FAIL: clean message rejected: {}\n", e)),
    }

    // --- Message 2: tampered ciphertext must be rejected, buffer zeroed ----
    let got2 = match ipc_recv_blocking(me, cap, ep, &mut buf) {
        Some(g) => g,
        None => task::task_exit(me),
    };
    if got2 < n + TAG_LEN {
        serial::print(format_args!("[B] FAIL: short message {} bytes\n", got2));
        task::task_exit(me);
    }
    let mut tag3 = [0u8; TAG_LEN];
    tag3.copy_from_slice(&buf[n..got2]);
    let mut pt2 = [0xEEu8; ipc::MAX_MSG];
    match gcm_decrypt(&TEST_KEY, &TEST_IV, &buf[..n], &[], &tag3, &mut pt2[..n]) {
        Err("AUTH") => {
            let zeroed = pt2[..n].iter().all(|&b| b == 0);
            if zeroed {
                serial::print(format_args!(
                    "[B] tamper rejected, buffer zeroed\nREDOS IPC TAMPER PASS\n"
                ));
            } else {
                serial::print(format_args!("[B] FAIL: tamper path did not zero buffer\n"));
            }
        }
        Ok(()) => serial::print(format_args!("[B] FAIL: tampered message accepted\n")),
        Err(e) => serial::print(format_args!("[B] FAIL: unexpected error {}\n", e)),
    }

    serial::print(format_args!("[B] done\n"));
    task::task_exit(me)
}

/// ipc_recv wrapper that yields while the router has the task blocked.
/// CEP: CEP-1 | Complete
/// Fail: None on contract error (printed here, named, caller exits).
/// The scratch buffer is MAX_MSG + TAG_LEN so a wire message (ciphertext ||
/// tag, both within one MAX_MSG message) never truncates; the router
/// contract caps a single receive at MAX_MSG, so we pass the cap.
fn ipc_recv_blocking(me: usize, cap: usize, ep: usize, buf: &mut [u8]) -> Option<usize> {
    let recv_cap = buf.len().min(ipc::MAX_MSG);
    loop {
        // A direct delivery may have landed while we were blocked: the
        // router filled our registered buffer already. Consume it FIRST —
        // re-calling ipc_recv would drain a LATER mailbox message out of
        // order.
        {
            let ts = task::tasks();
            if ts[me].delivered {
                ts[me].delivered = false;
                return Some(ts[me].recv_len);
            }
        }
        match ipc::ipc_recv(me, table_b(), cap, ep, buf.as_mut_ptr(), recv_cap) {
            Ok(n) => return Some(n),
            Err(ipc::IpcRecvError::Block) => {
                task::schedule_from(me); // blocked; resumes here when woken
            }
            Err(ipc::IpcRecvError::Contract(e)) => {
                serial::print(format_args!("[B] FAIL: recv contract: {}\n", e));
                return None;
            }
        }
    }
}

// Scratch buffers (statics, not stack — the messages are 4 KiB-class and
// Phase 1 stacks are 16 KiB; keeping large buffers out of stacks is an
// explicit stack-budget decision, not an accident).
static mut CT_A: [u8; ipc::MAX_MSG] = [0; ipc::MAX_MSG];
static mut CT_A2: [u8; ipc::MAX_MSG] = [0; ipc::MAX_MSG];
static mut WIRE_A: [u8; ipc::MAX_MSG + TAG_LEN] = [0; ipc::MAX_MSG + TAG_LEN];
static mut RECV_B: [u8; ipc::MAX_MSG + TAG_LEN] = [0; ipc::MAX_MSG + TAG_LEN];

#[allow(static_mut_refs)]
fn ct_buffer_a() -> &'static mut [u8] {
    unsafe { &mut *core::ptr::addr_of_mut!(CT_A) }
}
#[allow(static_mut_refs)]
fn ct_buffer_a2() -> &'static mut [u8] {
    unsafe { &mut *core::ptr::addr_of_mut!(CT_A2) }
}
#[allow(static_mut_refs)]
fn wire_buffer_a() -> &'static mut [u8] {
    unsafe { &mut *core::ptr::addr_of_mut!(WIRE_A) }
}
#[allow(static_mut_refs)]
fn recv_buffer_b() -> &'static mut [u8] {
    unsafe { &mut *core::ptr::addr_of_mut!(RECV_B) }
}
#[allow(static_mut_refs)]
fn table_a() -> &'static mut CTable {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE_A) }
}
#[allow(static_mut_refs)]
fn table_b() -> &'static mut CTable {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE_B) }
}

/// One-block encrypt/decrypt round trip against the C core.
/// CEP: CEP-2 | Complete (boot-time selftest)
fn crypto_selftest() -> Result<(), &'static str> {
    let pt = *b"REDOS selftest 1"; // 16 bytes
    let mut ct = [0u8; 16];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(&TEST_KEY, &TEST_IV, &pt, &[], &mut ct, &mut tag)?;
    let mut back = [0u8; 16];
    gcm_decrypt(&TEST_KEY, &TEST_IV, &ct, &[], &tag, &mut back)?;
    if back != pt {
        return Err("round-trip mismatch");
    }
    Ok(())
}

/// CEP: CEP-2 | Complete (cold diagnostic; explicit formatting cost)
/// Cost: O(mmap_len) with one formatted line per region (bounded 256).
fn report_memory_map(boot: &Handoff) {
    let mut usable_total: u64 = 0;
    let mut usable_regions: u64 = 0;

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
pub fn halt_forever() -> ! {
    loop {
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) }
    }
}

/// CEP: CEP-2 | Complete (cold path)
#[cold]
pub fn panic_str(prefix: &str, reason: &str) -> ! {
    serial::write_str("\nKERNEL PANIC: ");
    serial::write_str(prefix);
    serial::write_str(reason);
    serial::write_str("\n");
    halt_forever();
}

/// CEP: CEP-2 | Complete (cold path)
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::write_str("\nKERNEL PANIC: ");
    if let Some(loc) = info.location() {
        serial::print(format_args!("{}:{}: ", loc.file(), loc.line()));
    }
    serial::print(format_args!("{}", info.message()));
    serial::write_str("\n");
    halt_forever();
}
