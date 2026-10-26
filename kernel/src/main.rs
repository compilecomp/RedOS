//! RedOS kernel — entry point (Phase 2, milestone v0.7.0: Zero-ID
//! Identity).
//!
//! Tasks A/B carry the v0.5.0 memory-physics milestone (isolation, wipe,
//! lock, zero-copy, revoke — kept green unchanged). Task C carries the
//! v0.6.0 vault scenario — now fully input-driven: the PIN arrives
//! through the UART input service (no PIN constant exists in this
//! binary) and the duress phase waits for the identity demo to finish.
//! Task S is the identity service (manifests, sandbox spawner, Permission
//! Tracker, operator prompt handshake); task D is the sandboxed demo
//! program spawned from a signed manifest.
//!
//!   kmain
//!   ------------------------------------------------
//!   1. RNG policy (compile-time const) + entropy gate
//!   2. VAULT-PIN: typed by the operator/CI feeder -> vault sealed
//!   3. RNG-policy decision table asserted (both directions)
//!   4. endpoints + caps + bootstrap DISK grant for C (tracked)
//!   5. spawn B, A (memphy), C (vault client), S (identity service)
//!
//!   Task C (vault client)
//!   ------------------------------------------------
//!   1. wrong PIN #1 (test vector) -> tag failure, counter 1
//!   2. UNLOCK-PIN: typed through the input service -> unlock OK
//!   3. signals S (vault open) via the completion endpoint
//!   4. lease (owner-bound) + XTS disk round-trip (authority-checked)
//!   5. waits for S's completion signal, then wrong PIN #2 (budget)
//!      -> DURESS dead-man wipe -> fail-closed disk read
//!
//!   Task S (identity service) + Task D (sandboxed demo)
//!   ------------------------------------------------
//!   1. forged manifest (bad MAC) refused; substituted binary (bad
//!      hash) refused; valid manifest spawns D (fresh root, RO code
//!      window, default PROMPT grant)
//!   2. D: W^X probe on its code window (read OK, write denied)
//!   3. D: lease ttl over the STRICT cap -> mechanical denial
//!   4. D: lease request -> operator y -> owner-bound lease works,
//!      theft refused, expires, tracker records Expired
//!   5. D: disk request -> operator n -> disk use refused (NotGranted)
//!   6. D exits -> session caps revoked; S audits the tracker ledger
//!
//! CI banners (asserted by scripts/boot_test.sh, in addition to MEMPHY
//! and KMS banners):
//!   REDOS RNG-POLICY PASS          — decision table + live source
//!   REDOS INPUT PASS               — PIN consumed via the input service
//!   REDOS IDNT MAC-REFUSED         — forged manifest refused
//!   REDOS IDNT HASH-REFUSED        — substituted binary refused
//!   REDOS IDNT SPAWN PASS          — sandbox spawn under valid manifest
//!   REDOS IDNT W^X PASS            — code window read OK, write denied
//!   REDOS IDNT POLICY-REFUSED      — ttl over STRICT cap, no prompt
//!   REDOS IDNT LEASE-BOUND PASS    — lease theft refused, owner use OK
//!   REDOS IDNT LEASE-EXPIRED PASS  — lease TTL expiry (lazy)
//!   REDOS IDNT PROMPT-DENIED PASS  — operator n -> disk use refused
//!   REDOS IDNT TRACKER PASS        — ledger complete, session death
//!   REDOS IDNT TEST COMPLETE       — all observed in one boot
//!
//! CEP: CEP-1 | Complete (Phase 2 scope)
//! Cost: cold boot path + Argon2id seal at init + three task bodies.
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
mod identity;
mod input;
mod ipc;
mod kms;
mod mm;
mod ramdisk;
mod serial;
mod shm;
mod task;

use cap::RW;
use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use ffi::{gcm_decrypt, gcm_encrypt, IV_LEN, KEY_LEN, TAG_LEN};
use handoff::Handoff;
use identity::{
    DEC_DENIED, DEC_GRANTED, DEMO_BASE, KIND_DISK, KIND_DONE, KIND_EXPIRED, KIND_LEASE,
    REQ_LEN, STRICT_LEASE_TTL_MAX,
};
use input::Echo;
use ipc::IpcSendError;
use mm::idt;
use mm::pagemap::{self, hhdm, hhdm_mut, PRIV_ALT, PRIV_BASE, SHM_BASE};
use mm::phys::{self, PageClass, PAGE_SIZE};

/// Entropy policy (v0.7.0): the compile-time policy switch. Lenient
/// admits the documented weak TSC fallback with a loud log line — that
/// is what QEMU's default TCG CPU (no RDRAND) needs for CI. PRODUCTION
/// BUILDS SET STRICT (the vault then refuses to generate a master key
/// from anything but hardware RDRAND, entering the terminal Refused
/// state). The decision function itself is asserted in BOTH directions
/// by the RNG-policy banner regardless of which policy is live.
const RNG_POLICY: kms::RngPolicy = kms::RngPolicy::Lenient;

/// Wrong-PIN test vector. NOT a secret and NOT the operator's PIN: it is
/// a public counter-probe input for the duress scenario (the real PIN
/// arrives through the input service and never appears in this source).
const WRONG_PIN: &[u8] = b"wrong-pin-0000";
/// Comms-crypto demo key for the A/B zero-copy path (unchanged scope).
const TEST_KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const TEST_IV: [u8; IV_LEN] = [0x07; IV_LEN];
const PLAINTEXT: &[u8] = b"SOVEREIGN-ZERO-COPY-FROM-REDOS-PHASE2";

/// Task table indices assigned by kmain at spawn time. Atomics because the
/// compiler must not assume aliasing freedom across the context-switch asm
/// boundary; values are written once by kmain before any task runs.
static TASK_A: AtomicUsize = AtomicUsize::new(0);
static TASK_B: AtomicUsize = AtomicUsize::new(0);
static TASK_C: AtomicUsize = AtomicUsize::new(0);
static TASK_S: AtomicUsize = AtomicUsize::new(0);

/// Endpoint index created by kmain (write-once; see TASK_A note).
static EP: AtomicUsize = AtomicUsize::new(0);
/// Prompt-endpoint index (identity service requests/replies).
static EP_PROMPT: AtomicUsize = AtomicUsize::new(0);
/// Completion-endpoint index (C's open signal, S's done signal).
static EP_DONE: AtomicUsize = AtomicUsize::new(0);
/// Endpoint capability slot per task (write-once).
static CAP_A: AtomicUsize = AtomicUsize::new(0);
/// Endpoint capability slot for task B (write-once).
static CAP_B: AtomicUsize = AtomicUsize::new(0);
/// Capability slot of C's completion-endpoint cap (write-once).
static CAP_C_DONE: AtomicUsize = AtomicUsize::new(0);
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

    serial::print(format_args!(
        "\n=== RedOS v0.7.0 kernel (Zero-ID Identity) ===\n"
    ));

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

    // --- Entropy policy (v0.7.0) ------------------------------------------
    kms::set_rng_policy(RNG_POLICY);

    // --- RAM-only KMS vault: seal under the OPERATOR's PIN ----------------
    // The PIN is typed (operator on hardware, CI feeder in tests) through
    // the input service — masked echo, no PIN constant in this binary.
    // kmain tight-polls (slot 0, nothing else runnable yet). Argon2id
    // seal runs here (~8 MiB, t=2 — the boot pays it once).
    let mut pin = [0u8; 64];
    let mut pin_len = 0usize;
    for attempt in 0..3u32 {
        match input::read_line("VAULT-PIN: ", Echo::Masked, 0, &mut pin) {
            Ok(n) if n > 0 => {
                pin_len = n;
                break;
            }
            Ok(_) => {
                serial::print(format_args!(
                    "[boot] empty PIN (attempt {}/3) — retype\n",
                    attempt + 1
                ));
            }
            Err(e) => panic_str("vault pin: ", e),
        }
    }
    if pin_len == 0 {
        panic_str("vault pin: ", "no operator input at seal (3 attempts)");
    }
    kms::init(&pin[..pin_len]);
    // The PIN copy on kmain's stack must not outlive the seal.
    for b in pin.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::hint::black_box(&mut pin);
    if kms::status() == "REFUSED" {
        // Strict policy + weak entropy: the vault honestly refused to
        // exist. The scenario cannot proceed — fail the boot loudly.
        panic_str("kms: ", "vault REFUSED under RNG policy — scenario aborted");
    }

    // RNG-policy decision table, asserted in BOTH directions (the pure
    // function is the policy; the live policy + source are reported).
    let strict_refuses_weak = !kms::rng_admits(kms::RngPolicy::Strict, "tsc-fallback(WEAK)");
    let strict_admits_hw = kms::rng_admits(kms::RngPolicy::Strict, "rdrand");
    let lenient_admits_weak = kms::rng_admits(kms::RngPolicy::Lenient, "tsc-fallback(WEAK)");
    if strict_refuses_weak && strict_admits_hw && lenient_admits_weak {
        serial::print(format_args!(
            "[rng] policy {:?}; live entropy '{}'; strict refuses weak: yes; strict admits RDRAND: yes\nREDOS RNG-POLICY PASS\n",
            kms::rng_policy(),
            kms::last_entropy_source()
        ));
    } else {
        serial::print(format_args!(
            "[boot] FAIL: RNG decision table inconsistent (weak/refused={} hw/admitted={} lenient/admitted={})\n",
            strict_refuses_weak, strict_admits_hw, lenient_admits_weak
        ));
    }

    // --- Endpoints and capabilities (v0.7.0 wiring) -----------------------
    let ep = ipc::create_endpoint();
    EP.store(ep, Ordering::Relaxed);
    let ep_prompt = ipc::create_endpoint();
    EP_PROMPT.store(ep_prompt, Ordering::Relaxed);
    let ep_done = ipc::create_endpoint();
    EP_DONE.store(ep_done, Ordering::Relaxed);

    // kmain's slot 0 is NEVER a scheduling target — a documented
    // invariant, made explicit here as defense in depth: the scan in
    // schedule_from/yield_tick selects Runnable slots only, and slot 0
    // is born Free (never spawnable), so the marking is belt-and-
    // suspenders for any future state-machine change (v0.6.0 bring-up
    // drove this home: a yield that halts when alone — schedule_from —
    // is the wrong primitive for a clock tick; see yield_tick).
    tasks()[0].state = task::TaskState::Dead;

    // Spawn B first: it builds its root, maps its private page, and blocks
    // on recv — so A's cross-space probe and transfer are deterministic.
    let b = task::spawn(memphy_b, 0);
    TASK_B.store(b, Ordering::Relaxed);
    let a = task::spawn(memphy_a, 0);
    TASK_A.store(a, Ordering::Relaxed);
    let c = task::spawn(vault_c, 0);
    TASK_C.store(c, Ordering::Relaxed);

    // Caps for the demo tasks (per-task tables now live in cap.rs).
    let cap_a = cap::table_of(a)
        .mint(ep, RW)
        .unwrap_or_else(|e| panic_str("mint A: ", e));
    let cap_b = cap::table_of(b)
        .mint(ep, RW)
        .unwrap_or_else(|e| panic_str("mint B: ", e));
    CAP_A.store(cap_a, Ordering::Relaxed);
    CAP_B.store(cap_b, Ordering::Relaxed);
    let cap_c_done = cap::table_of(c)
        .mint(ep_done, RW)
        .unwrap_or_else(|e| panic_str("mint C(done): ", e));
    CAP_C_DONE.store(cap_c_done, Ordering::Relaxed);
    // Bootstrap authority for C (disk I/O) — recorded like any grant.
    identity::bootstrap_grant(c, identity::AUTH_DISK);

    // Identity service: spawn S, mint its caps, configure, then the
    // scheduler takes over. S blocks on the completion endpoint until C
    // signals the vault is open, so the config/caps below are in place
    // before S's first recv runs (cooperative model: S cannot run before
    // kmain reaches scheduler_run).
    let s = task::spawn(ident_service_entry, 0);
    TASK_S.store(s, Ordering::Relaxed);
    let cap_s_prompt = cap::table_of(s)
        .mint(ep_prompt, RW)
        .unwrap_or_else(|e| panic_str("mint S(prompt): ", e));
    let cap_s_done = cap::table_of(s)
        .mint(ep_done, RW)
        .unwrap_or_else(|e| panic_str("mint S(done): ", e));
    identity::configure(identity::Config {
        ep_prompt,
        ep_done,
        cap_prompt: cap_s_prompt,
        cap_done: cap_s_done,
        demo_entry: (sandbox_demo_body as extern "C" fn(u64) -> !) as usize as u64,
        decoy_entry: (vault_c as extern "C" fn(u64) -> !) as usize as u64,
    });
    serial::print(format_args!(
        "[boot] endpoints: demo={} prompt={} done={}\n",
        ep, ep_prompt, ep_done
    ));
    serial::print(format_args!(
        "[boot] tasks spawned: A={} B={} C={} S={}\n",
        a, b, c, s
    ));

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
    let slot_b = shm::transfer(block, root_a, root_b, cap::table_of(b))
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
    match ipc::ipc_send(me, cap::table_of(me), cap, ep, &desc) {
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
    let rights = cap::table_of(me)
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
    match shm::revoke(root_now, cap::table_of(me), slot, block) {
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

// --- Task C: RAM-only KMS vault scenario (input-driven, v0.7.0) -------------

/// Sector pattern for the XTS round-trip (recognizable, not self-symmetric
/// under 16-byte alignment: every 16-byte block differs).
const DISK_PATTERN: [u8; ramdisk::SECTOR_SIZE] = {
    let mut p = [0u8; ramdisk::SECTOR_SIZE];
    let mut i = 0;
    while i < ramdisk::SECTOR_SIZE {
        p[i] = (i as u8).wrapping_mul(0x5B).wrapping_add(0x11);
        i += 1;
    }
    p
};

/// Task C: wrong-PIN counter probe (test vector), operator-typed unlock
/// through the input service, vault-open signal to S, owner-bound lease
/// lifecycle, XTS disk round-trip under the tracker's authority gate,
/// then — after S's completion signal — the duress dead-man wipe and
/// fail-closed reads.
/// CEP: CEP-1 | Complete
/// Cost: four unlock calls (3 run Argon2id, the duress one refuses before
///       crypto); 2 BLAKE2b per disk op; O(1) leases.
/// Fail: FAIL lines for assertion breaches (recorded by CI); panics on
///       kernel-contract breaches (fail-fast).
extern "C" fn vault_c(_arg: u64) -> ! {
    let me = TASK_C.load(Ordering::Relaxed);
    use kms::UnlockError;

    serial::print(format_args!(
        "[C] vault status: {} (attempts used: {})\n",
        kms::status(),
        kms::attempts_used()
    ));

    // --- 1. wrong PIN (public test vector): tag failure, counter honest -----
    match kms::unlock(WRONG_PIN) {
        Err(UnlockError::WrongPin { remaining }) => {
            serial::print(format_args!(
                "[C] wrong PIN #1 rejected by GCM tag ({} attempts left)\n",
                remaining
            ));
            if remaining == kms::MAX_ATTEMPTS - 1 {
                serial::print(format_args!("REDOS KMS SEAL PASS\n"));
            } else {
                serial::print(format_args!("[C] FAIL: counter wrong ({})\n", remaining));
            }
        }
        Err(UnlockError::Dead) => {
            serial::print(format_args!("[C] FAIL: vault died on attempt #1\n"));
        }
        Err(other) => {
            serial::print(format_args!("[C] FAIL: unexpected unlock error {:?}\n", other));
        }
        Ok(()) => {
            serial::print(format_args!("[C] FAIL: wrong PIN ACCEPTED\n"));
        }
    }

    // --- 2. operator's PIN through the input service --------------------------
    // The unlock PIN is TYPED (masked echo; the log carries only stars).
    // Empty lines are retried — an accidental empty submit must not burn
    // the wrong-PIN budget.
    let mut pin = [0u8; 64];
    let mut pin_len = 0usize;
    for attempt in 0..3u32 {
        match input::read_line("UNLOCK-PIN: ", Echo::Masked, me, &mut pin) {
            Ok(n) if n > 0 => {
                pin_len = n;
                break;
            }
            Ok(_) => serial::print(format_args!(
                "[C] empty PIN (attempt {}/3) — retype\n",
                attempt + 1
            )),
            Err(e) => panic_str("unlock pin: ", e),
        }
    }
    match kms::unlock(&pin[..pin_len]) {
        Ok(()) => {
            let mf = kms::master_frame_phys();
            let bf = kms::blob_frame_phys();
            let mclass = phys::class_of(mf);
            let bclass = phys::class_of(bf);
            serial::print(format_args!(
                "[C] vault {} (attempts used: {}); PIN consumed via input service ({} chars, masked)\n",
                kms::status(),
                kms::attempts_used(),
                pin_len
            ));
            if mclass == PageClass::Locked && bclass == PageClass::Locked {
                serial::print(format_args!(
                    "REDOS KMS UNLOCK PASS\nREDOS INPUT PASS\n"
                ));
            } else {
                serial::print(format_args!(
                    "[C] FAIL: key frames not Locked (m/{:?} b/{:?})\n",
                    mclass, bclass
                ));
            }
        }
        Err(other) => {
            serial::print(format_args!(
                "[C] FAIL: operator PIN rejected: {:?}\n",
                other
            ));
        }
    }
    // The PIN copy leaves through the scrub (same hygiene as kmain's seal).
    for b in pin.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::hint::black_box(&mut pin);

    // --- 3. signal S: the vault is open (identity demo may start) ------------
    // S is blocked-recv on the completion endpoint: direct delivery, no
    // blocking path. The delivery IS the synchronization.
    let ep_done = EP_DONE.load(Ordering::Relaxed);
    let cap_done = CAP_C_DONE.load(Ordering::Relaxed);
    match ipc::ipc_send(me, cap::table_of(me), cap_done, ep_done, b"O") {
        Ok(()) => serial::print(format_args!("[C] vault-open signal sent to S\n")),
        Err(IpcSendError::Block) => {
            // S not waiting? A contract breach of the scenario's ordering.
            panic_str("C: ", "open signal blocked (S not recv-waiting)");
        }
        Err(IpcSendError::Contract(e)) => panic_str("C: open signal: ", e),
    }

    // --- 4. owner-bound lease lifecycle --------------------------------------
    match kms::lease_grant(2, me) {
        Ok(id) => {
            match kms::lease_use(id, me) {
                Ok(k) => {
                    let nonzero = k.iter().any(|&b| b != 0);
                    serial::print(format_args!(
                        "[C] lease {} granted (owner=me) and used (key nonzero: {})\n",
                        id, nonzero
                    ));
                }
                Err(e) => serial::print(format_args!("[C] FAIL: fresh lease denied {:?}\n", e)),
            }
            // Two scheduler switches: ticks advance (any interleaving with
            // A/B/S/D only advances ticks further — expiry is monotone).
            // yield_tick, not schedule_from: a self-switch still bumps the
            // tick, and the yield can never halt when others are already done.
            task::yield_tick(me);
            task::yield_tick(me);
            match kms::lease_use(id, me) {
                Err(kms::KmsError::Expired) => {
                    serial::print(format_args!(
                        "[C] lease expired after budget: key zeroized, use denied\nREDOS KMS LEASE PASS\n"
                    ));
                }
                Ok(_) => {
                    serial::print(format_args!("[C] FAIL: expired lease STILL USABLE\n"));
                }
                Err(e) => {
                    serial::print(format_args!("[C] FAIL: lease error {:?}\n", e));
                }
            }
        }
        Err(e) => serial::print(format_args!("[C] FAIL: lease grant {:?}\n", e)),
    }

    // --- 5. XTS RAM disk: round-trip + encryption-at-rest evidence -----------
    ramdisk::create();
    let sector = 5usize;
    match ramdisk::write_sector(me, sector, &DISK_PATTERN) {
        Ok(()) => serial::print(format_args!(
            "[C] sector {} written (XTS-AES-256, data unit = sector number; tracker DISK authority checked)\n",
            sector
        )),
        Err(e) => {
            serial::print(format_args!("[C] FAIL: disk write: {:?}\n", e));
            task::task_exit(me);
        }
    }
    let mut back = [0u8; ramdisk::SECTOR_SIZE];
    let mut raw = [0u8; ramdisk::SECTOR_SIZE];
    let mut roundtrip_ok = false;
    match ramdisk::read_sector(me, sector, &mut back) {
        Ok(()) => {
            if back == DISK_PATTERN {
                serial::print(format_args!(
                    "[C] sector {} read back: 512/512 bytes match\nREDOS RAMDISK ROUND-TRIP PASS\n",
                    sector
                ));
                roundtrip_ok = true;
            } else {
                let mut diff = 0usize;
                for i in 0..ramdisk::SECTOR_SIZE {
                    if back[i] != DISK_PATTERN[i] {
                        diff += 1;
                    }
                }
                serial::print(format_args!(
                    "[C] FAIL: round-trip mismatch ({} bytes differ)\n",
                    diff
                ));
            }
        }
        Err(e) => serial::print(format_args!("[C] FAIL: disk read: {:?}\n", e)),
    }
    ramdisk::raw_sector(sector, &mut raw);
    let plaintext_leak = raw == DISK_PATTERN;
    if !plaintext_leak {
        serial::print(format_args!(
            "[C] at-rest bytes of sector {} are ciphertext (raw != plaintext)\nREDOS RAMDISK CIPHERTEXT PASS\n",
            sector
        ));
    } else {
        serial::print(format_args!(
            "[C] FAIL: sector stored as PLAINTEXT — encryption at rest broken\n"
        ));
    }
    if !roundtrip_ok {
        // Round-trip already printed its FAIL line; keep the evidence
        // chain honest by refusing the downstream duress assertions.
        serial::print(format_args!("[C] FAIL: disk round-trip failed — aborting scenario\n"));
        task::task_exit(me);
    }

    // --- 6. wait for S's completion signal, then duress ----------------------
    // The identity demo must finish while the vault is alive: D's lease
    // authority only exists in the Unlocked state. C blocks here until S
    // has audited the tracker and sent the done signal. The wrapper (not
    // a bare ipc_recv): after a direct delivery the `delivered` flag IS
    // the message — re-calling ipc_recv would re-register and wait
    // forever (the v0.3.0 out-of-order lesson, relearned in v0.7.0).
    let mut buf = [0u8; 8];
    let ep_done = EP_DONE.load(Ordering::Relaxed);
    let cap_done = CAP_C_DONE.load(Ordering::Relaxed);
    let n = match ipc_recv_blocking(me, cap_done, ep_done, &mut buf) {
        Some(n) => n,
        None => panic_str("C: ", "done recv contract"),
    };
    serial::print(format_args!(
        "[C] completion signal from S ({} bytes) — identity demo finished\n",
        n
    ));

    // --- 7. duress: the counter's final wrong PIN destroys the vault ---------
    match kms::unlock(WRONG_PIN) {
        Err(UnlockError::Dead) => {
            serial::print(format_args!(
                "[C] wrong PIN #2 (budget): dead-man wipe fired -> vault {}\n",
                kms::status()
            ));
        }
        Err(UnlockError::WrongPin { remaining }) => {
            serial::print(format_args!(
                "[C] FAIL: expected DURESS at budget, got WrongPin ({} left)\n",
                remaining
            ));
        }
        other => {
            serial::print(format_args!("[C] FAIL: unexpected duress result {:?}\n", other));
        }
    }
    // Evidence: master frame zeroized, class still Locked (owner-only path).
    let mf = kms::master_frame_phys();
    let mut residue = 0usize;
    for k in 0..(PAGE_SIZE / 8) {
        let p = hhdm(mf + k * 8) as *const u64;
        if unsafe { p.read_volatile() } != 0 {
            residue += 1;
        }
    }
    let mclass_after = phys::class_of(mf);
    if residue == 0 && mclass_after == PageClass::Locked && kms::status() == "DEAD" {
        serial::print(format_args!(
            "[C] master frame zeroized ({} residue words), still Locked, vault DEAD\n",
            residue
        ));
    } else {
        serial::print(format_args!(
            "[C] FAIL: duress incomplete (residue={}, class={:?}, state={})\n",
            residue, mclass_after, kms::status()
        ));
    }

    // --- 8. fail-closed I/O after duress --------------------------------------
    match ramdisk::read_sector(me, sector, &mut back) {
        Err(ramdisk::DiskError::VaultDead) => {
            serial::print(format_args!(
                "[C] disk read after duress denied (VaultDead) — fail-closed\nREDOS KMS DURESS PASS\nREDOS KMS TEST COMPLETE\n"
            ));
        }
        Ok(()) => {
            serial::print(format_args!(
                "[C] FAIL: disk read SUCCEEDED after duress — key material survived\n"
            ));
        }
        Err(e) => {
            serial::print(format_args!(
                "[C] FAIL: expected VaultDead, got {:?}\n",
                e
            ));
        }
    }

    serial::print(format_args!("[C] done\n"));
    task::task_exit(me)
}

// --- Task D: the sandboxed demo program (spawned from a manifest) -----------

/// Task D — the "binary" the identity demo spawns. Its ENTRY BYTES are
/// what the manifest's content hash binds (fn_identity_hash over the
/// first 64 bytes of this function's code). Everything it does beyond
/// the default PROMPT grant goes through the operator prompt handshake.
///
/// Scenario: W^X probe on the spawn-granted code window -> lease request
/// over the STRICT ttl cap (mechanical denial) -> lease request within
/// policy (operator grants; theft refuses; expiry kills) -> disk request
/// (operator denies; use refuses) -> done.
/// CEP: CEP-1 | Complete
/// Cost: O(1) probes + 5 prompt round-trips + 2 yields.
/// Fail: FAIL lines for assertion breaches; panics on contract breaches.
extern "C" fn sandbox_demo_body(_arg: u64) -> ! {
    let me = identity::sandbox_task();
    let cap = identity::sandbox_cap();
    let ep = identity::prompt_ep();

    serial::print(format_args!(
        "[D] sandbox live: slot {}, code window at {:#x}\n",
        me, DEMO_BASE
    ));

    // --- 1. W^X: the spawn-granted window is readable, NOT writable --------
    let readable = idt::probe_read(DEMO_BASE).is_some();
    let writable = idt::probe_write(DEMO_BASE, 0xDEAD_BEEF_CAFE_F00D);
    if readable && !writable {
        serial::print(format_args!(
            "[D] code window: read OK, write DENIED by MMU (sandbox W^X surface)\nREDOS IDNT W^X PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[D] FAIL: code window readable={} writable={} — sandbox mapping broken\n",
            readable, writable
        ));
    }

    // --- 2. lease request over the STRICT policy cap: mechanical denial -----
    let (dec, _lease, _exp) = sandbox_request(me, cap, ep, KIND_LEASE, STRICT_LEASE_TTL_MAX + 1);
    if dec == DEC_DENIED {
        serial::print(format_args!(
            "[D] ttl {} over the STRICT cap: denied mechanically (S recorded it)\n",
            STRICT_LEASE_TTL_MAX + 1
        ));
    } else {
        serial::print(format_args!("[D] FAIL: policy cap DID NOT deny\n"));
    }

    // --- 3. lease request within policy: operator grants ---------------------
    let (dec, lease_id, _exp) = sandbox_request(me, cap, ep, KIND_LEASE, 2);
    if dec != DEC_GRANTED {
        serial::print(format_args!(
            "[D] FAIL: in-policy lease request denied (dec={})\n",
            dec
        ));
        task::task_exit(me);
    }
    let lease_id = lease_id as usize;
    serial::print(format_args!(
        "[D] lease {} granted by operator (ttl 2)\n",
        lease_id
    ));

    // --- 4. lease binding: a wrong owner cannot use it ------------------------
    // The owner parameter is caller-supplied in the Phase-2 model (ring 3
    // makes it structural in v0.8.0) — the BINDING is what's enforced and
    // tested: a use that names any other task refuses.
    let wrong_owner = if me > 1 { me - 1 } else { me + 1 };
    match kms::lease_use(lease_id, wrong_owner) {
        Err(kms::KmsError::NoSuchLease) => {
            serial::print(format_args!(
                "[D] lease theft refused: owner {} sees NoSuchLease (indistinguishable from absence)\n",
                wrong_owner
            ));
        }
        Ok(_) => {
            serial::print(format_args!("[D] FAIL: lease use SUCCEEDED for a non-owner\n"));
        }
        Err(e) => {
            serial::print(format_args!("[D] FAIL: theft probe gave {:?}\n", e));
        }
    }
    match kms::lease_use(lease_id, me) {
        Ok(k) => {
            let nonzero = k.iter().any(|&b| b != 0);
            if nonzero {
                serial::print(format_args!(
                    "[D] owner use OK (key nonzero) — binding holds\nREDOS IDNT LEASE-BOUND PASS\n"
                ));
            } else {
                serial::print(format_args!("[D] FAIL: owner use returned a zero key\n"));
            }
        }
        Err(e) => serial::print(format_args!("[D] FAIL: owner use denied {:?}\n", e)),
    }

    // --- 5. expiry: two switches later the lease is dead ----------------------
    task::yield_tick(me);
    task::yield_tick(me);
    match kms::lease_use(lease_id, me) {
        Err(kms::KmsError::Expired) => {
            serial::print(format_args!(
                "[D] lease expired (lazy wipe at first touch)\nREDOS IDNT LEASE-EXPIRED PASS\n"
            ));
            // Report the expiry so the tracker ledger mirrors the KMS.
            let (rd, _, _) = sandbox_request(me, cap, ep, KIND_EXPIRED, lease_id as u64);
            if rd != DEC_GRANTED {
                serial::print(format_args!("[D] FAIL: expiry report refused\n"));
            }
        }
        Ok(_) => serial::print(format_args!("[D] FAIL: expired lease STILL USABLE (owner)\n")),
        Err(e) => serial::print(format_args!("[D] FAIL: expected Expired, got {:?}\n", e)),
    }

    // --- 6. disk request: operator denies; use must refuse -------------------
    let (dec, _, _) = sandbox_request(me, cap, ep, KIND_DISK, 0);
    if dec == DEC_DENIED {
        serial::print(format_args!("[D] disk authority denied by operator\n"));
    } else {
        serial::print(format_args!("[D] FAIL: expected operator denial for disk\n"));
    }
    let probe = [0u8; ramdisk::SECTOR_SIZE];
    match ramdisk::write_sector(me, 1, &probe) {
        Err(ramdisk::DiskError::NotGranted) => {
            serial::print(format_args!(
                "[D] disk write refused: NotGranted (tracker-enforced, fail-closed)\nREDOS IDNT PROMPT-DENIED PASS\n"
            ));
        }
        Ok(()) => {
            serial::print(format_args!(
                "[D] FAIL: disk write SUCCEEDED without authority\n"
            ));
        }
        Err(e) => serial::print(format_args!("[D] FAIL: expected NotGranted, got {:?}\n", e)),
    }

    // --- 7. done ---------------------------------------------------------------
    let (dec, _, _) = sandbox_request(me, cap, ep, KIND_DONE, 0);
    if dec == DEC_GRANTED {
        serial::print(format_args!("[D] demo complete\n"));
    }
    serial::print(format_args!("[D] done\n"));
    task::task_exit(me)
}

/// One request/reply round-trip over the prompt endpoint (D's side).
/// S is blocked-recv on this endpoint, so sends deliver directly; the
/// reply wakes D the same way.
/// CEP: CEP-1 | Complete
/// Cost: O(REQ_LEN) copies + one switch pair.
/// Fail: panics on contract breaches (a broken prompt channel is a
///       kernel-contract breach in the scenario, not a runtime condition).
fn sandbox_request(me: usize, cap_slot: usize, ep: usize, kind: u64, arg: u64) -> (u64, u64, u64) {
    let mut req = [0u8; REQ_LEN];
    req[0..8].copy_from_slice(&(me as u64).to_le_bytes());
    req[8..16].copy_from_slice(&kind.to_le_bytes());
    req[16..24].copy_from_slice(&arg.to_le_bytes());
    match ipc::ipc_send(me, cap::table_of(me), cap_slot, ep, &req) {
        Ok(()) => {}
        Err(IpcSendError::Block) => task::schedule_from(me),
        Err(IpcSendError::Contract(e)) => panic_str("D: request send: ", e),
    }
    // Reply: S delivers directly into our registered buffer while we are
    // blocked-recv here (the delivered flag path), or the recv succeeds
    // outright if the reply already sits in the mailbox.
    let mut rep = [0u8; REQ_LEN];
    let n = match ipc_recv_blocking(me, cap_slot, ep, &mut rep) {
        Some(n) => n,
        None => panic_str("D: ", "reply recv contract"),
    };
    if n != REQ_LEN {
        panic_str("D: ", "reply length mismatch");
    }
    let dec = u64::from_le_bytes(rep[0..8].try_into().unwrap());
    let lease = u64::from_le_bytes(rep[8..16].try_into().unwrap());
    let exp = u64::from_le_bytes(rep[16..24].try_into().unwrap());
    (dec, lease, exp)
}

/// Identity service entry wrapper (the spawn interface passes no closure;
/// S reads its own slot from the write-once atomic).
/// CEP: CEP-1 | Complete
/// Fail: never returns.
extern "C" fn ident_service_entry(_arg: u64) -> ! {
    let me = TASK_S.load(Ordering::Relaxed);
    identity::service(me)
}
/// ipc_recv wrapper that yields while the router has the task blocked.
/// Used by B (blind descriptor), C (completion signal) and D (prompt
/// replies) — the caller's own table via cap::table_of.
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
        match ipc::ipc_recv(me, cap::table_of(me), cap, ep, buf.as_mut_ptr(), recv_cap) {
            Ok(n) => return Some(n),
            Err(ipc::IpcRecvError::Block) => {
                task::schedule_from(me); // blocked; resumes here when woken
            }
            Err(ipc::IpcRecvError::Contract(e)) => {
                serial::print(format_args!(
                    "[task {}] FAIL: recv contract: {}\n",
                    me, e
                ));
                return None;
            }
        }
    }
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
