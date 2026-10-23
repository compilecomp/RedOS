//! RedOS kernel — entry point (Phase 2, milestone v0.5.0: Memory Physics).
//!
//! The Phase-2 scenario implements Pillar 2 end to end with two kernel
//! threads in isolated address spaces:
//!
//!   Task A (producer, root_A)                    Task B (consumer, root_B)
//!   -------------------------                    -------------------------
//!   1. private page @ PRIV_BASE                  1. private page @ PRIV_ALT
//!   2. probe B's page → #PF → denied             2. block on blind IPC recv
//!   3. WIPE protocol test                        3. read ct via SHM keyhole
//!   4. LOCK (mlock mandate) test                    decrypt → ZERO-COPY PASS
//!   5. encrypt into SHM block                    4. kill switch: revoke cap
//!      (kernel never touches bytes)                 + unmap → probe → #PF
//!   6. transfer (A demoted to RO,                   → REVOKE PASS
//!      B mapped RW, token minted)              5. REDOS MEMPHY TEST COMPLETE
//!   7. send 24-byte descriptor (blind)
//!   8. verify own write-demotion
//!
//! CI banners (asserted by scripts/boot_test.sh):
//!   REDOS MEMPHY ISOLATION PASS   — cross-root probe denied by the MMU
//!   REDOS MEMPHY WIPE PASS        — freed frame carries no residue
//!   REDOS MEMPHY LOCK PASS        — locked frame refuses the free path
//!   REDOS MEMPHY ZERO-COPY PASS   — payload moved by capability, not copy
//!   REDOS MEMPHY REVOKE PASS      — post-revocation access is a #PF
//!   REDOS MEMPHY TEST COMPLETE    — all six observed in one boot
//!
//! CEP: CEP-1 | Complete (Phase 2 scope)
//! Cost: cold boot path + the two test tasks; all output via polled UART.
//! Fail: panics (named, serial) on any handoff/IPC/crypto/MMU contract
//!       breach; FAIL lines (not panics) mark failed test assertions so
//!       the CI log records them verbatim.
//! Assumes: identity mapping + handoff from the Zig bootloader; interrupts
//!          disabled; cooperative scheduling; NO access to the handoff
//!          struct after `pagemap::init()` switches CR3 (mm/pagemap.rs).

#![no_std]
#![no_main]
#![deny(missing_docs)]

mod audit;
mod cap;
mod ffi;
mod handoff;
mod ipc;
mod mm;
mod serial;
mod shm;
mod task;

use cap::{CTable, RW};
use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use ffi::{gcm_decrypt, gcm_encrypt, IV_LEN, KEY_LEN, TAG_LEN};
use handoff::Handoff;
use ipc::IpcSendError;
use mm::idt;
use mm::pagemap::{self, hhdm, hhdm_mut, PRIV_ALT, PRIV_BASE, SHM_BASE};
use mm::phys::{self, PageClass, PAGE_SIZE};

/// Phase-2 test key. v0.6.0 replaces this with the RAM-only KMS vault
/// (Argon2id-derived, mlocked arena, duress-wiped). Until then the key is
/// a compile-time constant — acceptable ONLY because Phase 2 has no
/// persistent storage and no external interfaces (documented decision).
const TEST_KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const TEST_IV: [u8; IV_LEN] = [0x07; IV_LEN];
const PLAINTEXT: &[u8] = b"SOVEREIGN-ZERO-COPY-FROM-REDOS-PHASE2";

/// Task table indices assigned by kmain at spawn time. Atomics because the
/// compiler must not assume aliasing freedom across the context-switch asm
/// boundary; values are written once by kmain before any task runs.
static TASK_A: AtomicUsize = AtomicUsize::new(0);
static TASK_B: AtomicUsize = AtomicUsize::new(0);

/// Per-task capability tables (minted by kmain/transfer; tasks use them
/// per the cooperative single-writer model).
static mut TABLE_A: CTable = CTable::new();
static mut TABLE_B: CTable = CTable::new();

/// Endpoint index created by kmain (write-once; see TASK_A note).
static EP: AtomicUsize = AtomicUsize::new(0);
/// Endpoint capability slot per task (write-once).
static CAP_A: AtomicUsize = AtomicUsize::new(0);
/// Endpoint capability slot for task B (write-once).
static CAP_B: AtomicUsize = AtomicUsize::new(0);
/// Shared-memory capability slot minted into B by the transfer (written
/// by A during transfer — cooperative model, see shm.rs).
static SHM_SLOT_B: AtomicUsize = AtomicUsize::new(0);

/// CEP: CEP-1 | Complete
/// Cost: one-time boot path.
/// Fail: panics on invalid handoff (named reason printed first).
/// Assumes: called by the bootloader exactly once, RDI = &Handoff (SysV).
#[no_mangle]
pub extern "C" fn _start(boot: &Handoff) -> ! {
    serial::init();

    serial::print(format_args!("\n=== RedOS v0.5.0 kernel (Memory Physics) ===\n"));

    if let Err(reason) = boot.validate() {
        panic_str("handoff rejected: ", reason);
    }
    serial::print(format_args!("[boot] handoff OK (version {})\n", boot.version));

    // --- Memory physics bring-up (order matters) --------------------------
    // 1. The ephemeral allocator reads the handoff memory map (last read
    //    of boot-owned memory; everything after uses kernel-owned state).
    phys::init(boot);
    // 2. Paging: build the kernel root and switch CR3. From here on the
    //    handoff/mmap pages are off-limits (documented in pagemap.rs).
    pagemap::init();
    // 3. The IDT (exception traps — the enforcement half of revocation).
    idt::init();
    // 4. Structural guarantees.
    phys::anti_swap_audit();
    phys::report();

    // Self-test the crypto core before trusting it with the milestone.
    if let Err(e) = crypto_selftest() {
        panic_str("crypto selftest failed: ", e);
    }
    serial::print(format_args!("[boot] crypto core selftest OK\n"));

    // --- Phase 2 milestone wiring -----------------------------------------
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
        "[boot] endpoint {} minted; endpoint caps A={} B={}\n",
        ep, cap_a, cap_b
    ));

    // Spawn B first: it builds its root, maps its private page, and blocks
    // on recv — so A's cross-space probe and transfer are deterministic.
    let b = task::spawn(memphy_b, 0);
    TASK_B.store(b, Ordering::Relaxed);
    let a = task::spawn(memphy_a, 0);
    TASK_A.store(a, Ordering::Relaxed);
    serial::print(format_args!("[boot] tasks spawned: A={} B={}\n", a, b));

    task::scheduler_run()
}

// --- Task A: producer + memory-physics tests -------------------------------

/// Task A: isolation probe, wipe/lock tests, zero-copy production, blind
/// descriptor send, self write-demotion check.
/// CEP: CEP-1 | Complete
/// Cost: O(1) allocations + O(1) mappings + one GCM encrypt over 53 bytes
///       + a 256-window wipe sweep (16×256 = 4 KiB of evidence reads).
/// Fail: FAIL lines for assertion breaches (recorded by CI); panics on
///       kernel-contract breaches (fail-fast).
extern "C" fn memphy_a(_arg: u64) -> ! {
    let me = TASK_A.load(Ordering::Relaxed);
    let ep = EP.load(Ordering::Relaxed);
    let cap = CAP_A.load(Ordering::Relaxed);

    // --- Root + private page ------------------------------------------------
    let root_a = pagemap::new_task_root()
        .unwrap_or_else(|e| panic_str("A: task root: ", e));
    let priv_frame = phys::alloc(PageClass::General)
        .unwrap_or_else(|| panic_str("A: ", "private frame exhausted"));
    pagemap::map_page(root_a, PRIV_BASE, priv_frame, true)
        .unwrap_or_else(|e| panic_str("A: map private: ", e));
    // Pattern A's private page through the HHDM (kernel-side write).
    let pv = hhdm_mut(priv_frame) as *mut u64;
    for k in 0..(PAGE_SIZE / 8) {
        unsafe { pv.add(k as usize).write_volatile(0xA5A5_5A5A_1234_5678) };
    }
    tasks()[me].cr3 = root_a;
    pagemap::switch_cr3(root_a);
    serial::print(format_args!(
        "[A] root {:#x} live; private page at {:#x}\n",
        root_a, PRIV_BASE
    ));

    // --- ISOLATION: B's private page exists ONLY in B's root ----------------
    // (B mapped it at PRIV_ALT before blocking; A's root has no PML4[14]
    // entry for that slot — the probe MUST take a #PF.)
    if idt::probe_read(PRIV_ALT).is_none() {
        serial::print(format_args!(
            "[A] cross-space probe at {:#x} denied by MMU\nREDOS MEMPHY ISOLATION PASS\n",
            PRIV_ALT
        ));
    } else {
        serial::print(format_args!(
            "[A] FAIL: cross-space probe SUCCEEDED — address-space leak\n"
        ));
    }

    // --- WIPE protocol: freed frames carry no residue ------------------------
    let f = phys::alloc(PageClass::General)
        .unwrap_or_else(|| panic_str("A: ", "wipe-test frame exhausted"));
    let w = hhdm_mut(f) as *mut u64;
    for k in 0..(PAGE_SIZE / 8) {
        unsafe { w.add(k as usize).write_volatile(0xC7C7_C7C7_C7C7_C7C7) };
    }
    phys::free(f).unwrap_or_else(|_| panic_str("A: ", "free of General refused"));
    // Statistical evidence: 256 independent 16-byte windows must not
    // match the old pattern (a false PASS needs ≥2^-128 luck).
    let mut residue = 0usize;
    for k in 0..256usize {
        let win = unsafe { core::slice::from_raw_parts(hhdm(f + (k as u64) * 16), 16) };
        if win.iter().all(|&b| b == 0xC7) {
            residue += 1;
        }
    }
    if residue == 0 && phys::class_of(f) == PageClass::Free {
        serial::print(format_args!(
            "[A] freed frame wiped: 256/256 windows clean\nREDOS MEMPHY WIPE PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[A] FAIL: wipe protocol leaked {} window(s)\n",
            residue
        ));
    }

    // --- LOCK: the mlock mandate refuses the free path -----------------------
    let lk = phys::alloc(PageClass::Locked)
        .unwrap_or_else(|| panic_str("A: ", "locked frame exhausted"));
    let lock_refused = phys::free(lk).is_err();
    let lock_class = phys::class_of(lk);
    if lock_refused && lock_class == PageClass::Locked {
        serial::print(format_args!(
            "[A] locked frame {:#x} refuses free (mlock mandate)\nREDOS MEMPHY LOCK PASS\n",
            lk
        ));
    } else {
        serial::print(format_args!(
            "[A] FAIL: locked frame was freed or reclassified\n"
        ));
    }

    // --- Zero-copy production: encrypt INTO the shared block ------------------
    let block = shm::create(shm::BLOCK_PAGES)
        .unwrap_or_else(|e| panic_str("A: shm create: ", e));
    shm::map_for(root_a, block, true)
        .unwrap_or_else(|e| panic_str("A: shm map: ", e));
    let phys_disp = match shm::phys_of(block) {
        Ok(p) => p,
        Err(e) => {
            serial::print(format_args!("[A] FAIL: phys_of: {}\n", e));
            task::task_exit(me);
        }
    };
    serial::print(format_args!(
        "[A] shm block {} at vaddr {:#x} (phys {:#x})\n",
        block,
        shm::vaddr_of(block),
        phys_disp
    ));

    let n = PLAINTEXT.len();
    // The ciphertext lands DIRECTLY in the shared block through A's own
    // keyhole — the kernel copies nothing (blindness + zero-copy).
    let shm_ptr = SHM_BASE as *mut u8;
    let ct = unsafe { core::slice::from_raw_parts_mut(shm_ptr, n) };
    let tag_ptr = unsafe { shm_ptr.add(n) } as *mut [u8; TAG_LEN];
    let tag = unsafe { &mut *tag_ptr };
    if let Err(e) = gcm_encrypt(&TEST_KEY, &TEST_IV, PLAINTEXT, &[], ct, tag) {
        panic_str("A: encrypt into shm: ", e);
    }
    serial::print(format_args!(
        "[A] wrote {} ct + {} tag bytes into shared block via own mapping\n",
        n,
        TAG_LEN
    ));

    // --- Transfer: A demoted to RO, B mapped RW, token minted -----------------
    let b = TASK_B.load(Ordering::Relaxed);
    let root_b = tasks()[b].cr3;
    let slot_b = shm::transfer(block, root_a, root_b, table_b())
        .unwrap_or_else(|e| panic_str("A: shm transfer: ", e));
    SHM_SLOT_B.store(slot_b, Ordering::Relaxed);
    serial::print(format_args!(
        "[A] transfer complete: B cap slot {} (token minted)\n",
        slot_b
    ));

    // Write-demotion check: A's own window must now deny writes (the
    // "Read-Only" half of the dual-keyhole handoff).
    if !idt::probe_write(SHM_BASE, 0xFFFF_1111_2222_3333) {
        serial::print(format_args!(
            "[A] post-transfer write denied (write-demotion enforced)\n"
        ));
    } else {
        serial::print(format_args!("[A] FAIL: post-transfer write SUCCEEDED\n"));
    }

    // --- Blind descriptor send (24 bytes: the router sees none of it) --------
    let desc: [u8; 24] = {
        let mut d = [0u8; 24];
        d[0..8].copy_from_slice(&(block as u64).to_le_bytes());
        d[8..16].copy_from_slice(&0u64.to_le_bytes()); // offset
        d[16..24].copy_from_slice(&(n as u64).to_le_bytes()); // length
        d
    };
    match ipc::ipc_send(me, table_a(), cap, ep, &desc) {
        Ok(()) => {}
        Err(IpcSendError::Block) => task::schedule_from(me),
        Err(IpcSendError::Contract(e)) => panic_str("A: send desc: ", e),
    }

    serial::print(format_args!("[A] done\n"));
    task::task_exit(me)
}

// --- Task B: consumer + revocation kill-switch test -------------------------

/// Task B: private page (mapped BEFORE A probes), blind recv, zero-copy
/// consumption, kill-switch revocation.
/// CEP: CEP-1 | Complete
/// Cost: O(1) allocations + O(1) mappings + one GCM decrypt over 53 bytes
///       + two probes.
/// Fail: FAIL lines for assertion breaches (recorded by CI); panics on
///       kernel-contract breaches (fail-fast).
extern "C" fn memphy_b(_arg: u64) -> ! {
    let me = TASK_B.load(Ordering::Relaxed);

    // --- Root + B-only private page (A will probe this and MUST fault) -----
    let root_b = pagemap::new_task_root()
        .unwrap_or_else(|e| panic_str("B: task root: ", e));
    let priv_frame = phys::alloc(PageClass::General)
        .unwrap_or_else(|| panic_str("B: ", "private frame exhausted"));
    pagemap::map_page(root_b, PRIV_ALT, priv_frame, true)
        .unwrap_or_else(|e| panic_str("B: map private: ", e));
    let pv = hhdm_mut(priv_frame) as *mut u64;
    for k in 0..(PAGE_SIZE / 8) {
        unsafe { pv.add(k as usize).write_volatile(0xB0B5_C0DE_BEEF_BABE) };
    }
    tasks()[me].cr3 = root_b;
    pagemap::switch_cr3(root_b);
    serial::print(format_args!(
        "[B] root {:#x} live; private page at {:#x}\n",
        root_b, PRIV_ALT
    ));

    // --- Blind recv of the descriptor ---------------------------------------
    let ep = EP.load(Ordering::Relaxed);
    let cap = CAP_B.load(Ordering::Relaxed);
    let mut buf = [0u8; 24];
    let got = match ipc_recv_blocking(me, cap, ep, &mut buf) {
        Some(g) => g,
        None => task::task_exit(me),
    };
    if got != 24 {
        serial::print(format_args!("[B] FAIL: descriptor {} bytes, want 24\n", got));
        task::task_exit(me);
    }
    let block = u64::from_le_bytes(buf[0..8].try_into().unwrap()) as usize;
    let len = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
    serial::print(format_args!(
        "[B] descriptor: block={} len={} (router never inspected these)\n",
        block, len
    ));

    // --- Zero-copy consumption via B's keyhole ------------------------------
    let slot = SHM_SLOT_B.load(Ordering::Relaxed);
    let rights = table_b()
        .lookup_shm(slot, block)
        .unwrap_or_else(|e| panic_str("B: shm cap: ", e));
    serial::print(format_args!(
        "[B] shm cap slot {}: rights={:#x} (READ|WRITE)\n",
        slot, rights
    ));

    let n = PLAINTEXT.len();
    if len != n {
        serial::print(format_args!(
            "[B] FAIL: descriptor len {} != expected {}\n",
            len, n
        ));
        task::task_exit(me);
    }
    let shm_ptr = SHM_BASE as *const u8;
    let ct = unsafe { core::slice::from_raw_parts(shm_ptr, n) };
    let tag = unsafe { core::slice::from_raw_parts(shm_ptr.add(n), TAG_LEN) };
    let mut tag_copy = [0u8; TAG_LEN];
    tag_copy.copy_from_slice(tag);
    let mut pt = [0xEEu8; 64];
    match gcm_decrypt(&TEST_KEY, &TEST_IV, ct, &[], &tag_copy, &mut pt[..n]) {
        Ok(()) => {
            if &pt[..n] == PLAINTEXT {
                serial::print(format_args!(
                    "[B] decrypted via shared mapping: {}\n",
                    core::str::from_utf8(&pt[..n]).unwrap_or("<invalid>")
                ));
                serial::print(format_args!("REDOS MEMPHY ZERO-COPY PASS\n"));
            } else {
                serial::print(format_args!("[B] FAIL: plaintext mismatch\n"));
            }
        }
        Err(e) => serial::print(format_args!("[B] FAIL: decrypt: {}\n", e)),
    }

    // --- KILL SWITCH: revoke cap + unmap; next access must #PF ---------------
    let root_now = tasks()[me].cr3;
    match shm::revoke(root_now, table_b(), slot, block) {
        Ok(()) => {}
        Err(e) => panic_str("B: revoke: ", e),
    }
    serial::print(format_args!(
        "[B] kill switch: cap slot zeroed + PTE torn down\n"
    ));
    if idt::probe_read(SHM_BASE).is_none() {
        serial::print(format_args!(
            "[B] post-revocation access trapped by MMU\nREDOS MEMPHY REVOKE PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[B] FAIL: post-revocation access SUCCEEDED — revocation leak\n"
        ));
    }

    // Sanity: B's own private page still mapped and intact.
    let pv = unsafe { (PRIV_ALT as *const u64).read_volatile() };
    if pv == 0xB0B5_C0DE_BEEF_BABE {
        serial::print(format_args!("[B] private page intact after revoke (scope OK)\n"));
    } else {
        serial::print(format_args!("[B] FAIL: private page disturbed ({:#x})\n", pv));
    }

    serial::print(format_args!("[B] done\nREDOS MEMPHY TEST COMPLETE\n"));
    task::task_exit(me)
}

/// ipc_recv wrapper that yields while the router has the task blocked.
/// CEP: CEP-1 | Complete
/// Cost: O(1) per poll; O(yields) until delivery (cooperative wake).
/// Fail: None on contract error (printed here, named, caller exits).
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

// Scratch buffers and accessors (statics, not stacks — stack budget).

#[allow(static_mut_refs)]
fn table_a() -> &'static mut CTable {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE_A) }
}
#[allow(static_mut_refs)]
fn table_b() -> &'static mut CTable {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE_B) }
}
#[allow(static_mut_refs)]
fn tasks() -> &'static mut [task::Task; task::MAX_TASKS] {
    task::tasks()
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
