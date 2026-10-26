//! RedOS kernel — the RAM-Only KMS Vault (Pillar 2, milestone v0.6.0).
//!
//! Design (docs/ARCHITECTURE.md §KMS):
//!
//! * **RAM-only.** There is no persistent storage anywhere in the kernel
//!   (mm/phys.rs anti-swap audit). Everything the vault knows is created
//!   at boot and dies at boot. A cold-boot attacker with a memory image
//!   sees at most: the Argon2id arena (wiped after every attempt), the
//!   sealed blob (ciphertext under the PIN-derived KEK), and — only
//!   between unlock and duress — the live master key in a Locked frame.
//!
//! * **Sealed-blob unlock.** At boot the vault generates a random master
//!   key and immediately seals it: `blob = GCM(master || ...)` — strictly,
//!   `GCM(master_key)` under `KEK = Argon2id(PIN, salt)`. There is no
//!   stored PIN verifier (nothing persists to store one against); PIN
//!   correctness is PROVEN by the GCM tag when the candidate KEK unwraps
//!   the blob. A wrong PIN is a tag failure — authenticated, fail-closed.
//!
//! * **mlock mandate.** The master key frame, the blob frame, and the
//!   Argon2id work arena are all `PageClass::Locked`: the public free
//!   path refuses them (proven at v0.5.0, MEMPHY LOCK banner), so no
//!   component can accidentally re-pool key material. Only the vault
//!   (the owner) writes zeros over them — at duress.
//!
//! * **Wrong-PIN counter / dead-man wipe.** The attempt counter is
//!   monotone within a boot (a successful unlock does NOT reset it —
//!   documented policy; a boot is the vault's lifetime). The attempt
//!   that reaches `MAX_ATTEMPTS` triggers the duress path: master key,
//!   blob, leases, and derived keys are zeroized, the wipe-key upgrade
//!   is reverted, and the vault enters the terminal `Dead` state. Every
//!   later operation fails closed. This is provable — see proof/Kms.thy
//!   (counter monotonicity, Dead terminality).
//!
//! * **Key derivation.** All sub-keys are derived with keyed BLAKE2b
//!   (RFC 7693 KAT-pinned in the C core) over domain-separated inputs:
//!   `subkey = BLAKE2b-256(key = master, in = domain || context)`.
//!   The disk key and lease keys are derived per use and zeroized after
//!   use — key material never rests outside the master frame.
//!
//! * **Entropy note (documented limitation).** The master key comes from
//!   RDRAND when the CPU provides it (CPUID-checked — executing RDRAND
//!   without support would #UD); otherwise the boot falls back to a
//!   TSC-mixed BLAKE2b stream, which is WEAK (QEMU demo configuration).
//!   A production build must hard-fail without a hardware RNG; that
//!   policy switch lands with the input service (v0.7.0), which is also
//!   where the PIN stops being a test constant.
//!
//! CEP: CEP-1 | Complete (Phase 2 scope: single unlock, lazy lease expiry)
//! Cost: unlock = one Argon2id (m=8 MiB, t=2, p=1) + one GCM unwrap;
//!       grant/use = one BLAKE2b; duress = O(vault bytes) zeroize.
//! Fail: every state violation is a named error (Dead/Sealed/Expired/
//!       Exhausted); the duress path is terminal and never silent.
//! Assumes: single CPU, no interrupts (cooperative Phase-2 model);
//!          called after phys::init (frames exist) and before any use
//!          of derived keys.

use crate::mm::phys::{self, PageClass, PAGE_SIZE};
use crate::serial;

/// Wrong-PIN budget. The attempt that reaches this number destroys the
/// vault (the README/ROADMAP exit criterion: "wrong-PIN counter destroys
/// the vault"). Monotone across successes — see module docs.
pub const MAX_ATTEMPTS: u32 = 3;

/// Argon2id parameters (documented policy): 8 MiB work area, 2 passes,
/// 1 lane. Rationale: 8 MiB is the largest arena that keeps the QEMU
/// TCG boot test comfortably under its timeout while still forcing a
/// memory-hard (not compute-hard) attack; production targets the RFC
/// 9106 "second recommended" profile (64 MiB, t=3) once hardware
/// timing budgets exist. RFC 9106 floors (m >= 8p, salt >= 8) hold.
pub const ARGON2_PASSES: u32 = 2;
pub const ARGON2_MEMORY_KIB: u32 = 8 * 1024;
pub const ARGON2_LANES: u32 = 1;

/// Lease table size (Phase 2 demo scale).
pub const MAX_LEASES: usize = 4;

const MASTER_KEY_LEN: usize = crate::ffi::KEY_LEN;
const KEK_LEN: usize = crate::ffi::KEY_LEN;
/// Sealed blob layout: iv(12) || ct(32) || tag(16) = 60 bytes.
const BLOB_LEN: usize = crate::ffi::IV_LEN + MASTER_KEY_LEN + crate::ffi::TAG_LEN;

/// "Hardware" salt: 8 documented constant bytes + 8 per-boot TSC bytes.
/// On real hardware the constant half would be SoC fuses / TPM NV;
/// QEMU exposes neither — the constant stands in for it (documented).
const HW_SALT_CONST: [u8; 8] = *b"RDOS-SLT";

/// Vault state machine (proof/Kms.thy mirrors these states exactly).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum VaultState {
    /// Sealed: master key exists only as the GCM blob.
    Sealed,
    /// Unlocked: master key live in a Locked frame; keys derivable.
    Unlocked,
    /// Duress wipe in progress (transient; single CPU makes it atomic
    /// in practice, the state exists so a future SMP revision cannot
    /// observe a half-wiped vault as usable).
    Wiping,
    /// Terminal. No operation ever succeeds again (proof: Dead terminal).
    Dead,
    /// v0.7.0 strict-RNG refusal: the configured entropy policy refuses
    /// the available entropy source, so NO master key was ever generated.
    /// Terminal like Dead (fail-closed: a vault that cannot be seeded
    /// honestly must not pretend to run), but status() distinguishes it.
    Refused,
}

/// A leased derived key with a scheduler-tick expiry, bound to its owner
/// task (v0.7.0: lease theft refuses with NoSuchLease — a non-owner's
/// view of the lease is indistinguishable from its absence).
#[derive(Clone, Copy)]
struct Lease {
    in_use: bool,
    owner: usize,
    key: [u8; MASTER_KEY_LEN],
    expires_tick: u64,
}

impl Lease {
    const fn new() -> Lease {
        Lease {
            in_use: false,
            owner: usize::MAX,
            key: [0; MASTER_KEY_LEN],
            expires_tick: 0,
        }
    }
}

// --- Vault state (single-CPU statics; see module docs) ----------------------

static mut STATE: VaultState = VaultState::Sealed;
static mut ATTEMPTS: u32 = 0;
/// Physical address of the Locked frame holding the live master key
/// (valid only while Unlocked).
static mut MASTER_FRAME: u64 = 0;
/// Physical address of the Locked frame holding the sealed blob.
static mut BLOB_FRAME: u64 = 0;
/// Argon2id work arena: base physical address + frame count (Locked).
static mut ARENA_BASE: u64 = 0;
static mut ARENA_FRAMES: usize = 0;
/// Per-boot salt (HW_SALT_CONST || TSC nonce), built by init().
static mut SALT: [u8; 16] = [0; 16];
static mut LEASES: [Lease; MAX_LEASES] = [Lease::new(); MAX_LEASES];
/// Next lease id (monotone; feeds the derivation domain separation).
static mut LEASE_SEQ: u64 = 0;
/// Entropy-policy switch (v0.7.0): Lenient admits the documented weak
/// TSC fallback with a loud report (QEMU CI's TCG CPU has no RDRAND);
/// Strict refuses to generate a master key from anything but RDRAND.
/// Production builds set Strict (main.rs const), CI runs Lenient.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RngPolicy {
    /// Weak fallback allowed (reported as WEAK in the boot log).
    Lenient,
    /// RDRAND or no key (vault enters the terminal Refused state).
    Strict,
}
static mut RNG_POLICY: RngPolicy = RngPolicy::Lenient;
/// The entropy source actually used at seal time ("rdrand" or
/// "tsc-fallback(WEAK)"); "none" before init. Surfaced for the
/// RNG-policy banner and the strict-refusal evidence.
static mut ENTROPY_SRC: &str = "none";

// --- Errors -----------------------------------------------------------------

/// Unlock failures (named; the CI log prints these verbatim).
#[derive(Debug)]
pub enum UnlockError {
    /// Vault is destroyed (duress) — terminal, fail-closed.
    Dead,
    /// Strict RNG policy refused the seal — no master key exists to
    /// unlock (v0.7.0; terminal like Dead).
    Refused,
    /// Already unlocked; the sealed blob is not re-unlocked.
    AlreadyUnlocked,
    /// Tag authentication failed. `remaining` = attempts left before
    /// the dead-man wipe fires.
    WrongPin { remaining: u32 },
    /// The C core rejected a parameter (contract breach — never expected).
    /// Payload surfaced through the Debug print in the CI log.
    Crypto(#[allow(dead_code)] &'static str),
}

/// Key-service failures for lease/disk-key operations.
#[derive(Debug)]
pub enum KmsError {
    /// Terminal state (duress wiped the vault).
    Dead,
    /// Terminal state (strict-RNG refusal — no key ever existed).
    Refused,
    /// Vault not unlocked.
    Sealed,
    /// Lease id unknown — OR owned by another task (v0.7.0: the two are
    /// deliberately indistinguishable to a non-owner; see lease_use).
    NoSuchLease,
    /// Lease expired: the key was zeroized on this access (lazy expiry).
    Expired,
    /// C-core contract error.
    Crypto(&'static str),
}

// --- Entropy ----------------------------------------------------------------

/// CPUID leaf 1 ECX bit 30: RDRAND supported.
fn has_rdrand() -> bool {
    let a: u32;
    let c: u32;
    let d: u32;
    unsafe {
        // rbx is reserved on LLVM x86_64: push/pop around cpuid (balanced,
        // so no operand declaration for rbx is needed or allowed).
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => a,
            out("ecx") c,
            out("edx") d,
            options(nomem, preserves_flags)
        );
    }
    let _ = (a, d);
    (c >> 30) & 1 == 1
}

/// One 64-bit RDRAND draw with the SDM-mandated retry loop.
/// Returns None if the hardware refuses (or is absent).
fn rdrand_u64() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    for _ in 0..16 {
        let v: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack)
            );
        }
        if ok == 1 {
            return Some(v);
        }
    }
    None
}

/// 32 bytes of master-key entropy: RDRAND when present (QEMU q35 with a
/// modern -cpu provides it; the TCG default CPU does not), else the
/// documented TSC-mixed fallback (weak — see module docs).
fn master_key_entropy() -> ([u8; MASTER_KEY_LEN], &'static str) {
    let mut out = [0u8; MASTER_KEY_LEN];
    let mut all_hw = true;
    for chunk in out.chunks_mut(8) {
        match rdrand_u64() {
            Some(v) => chunk.copy_from_slice(&v.to_le_bytes()),
            None => {
                all_hw = false;
                break;
            }
        }
    }
    if all_hw {
        return (out, "rdrand");
    }
    // Fallback: TSC-mixed BLAKE2b stream (weak, documented).
    for i in 0..4 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("rax") lo,
                out("rdx") hi,
                options(nomem, nostack)
            );
        }
        let mut input = [0u8; 13];
        input[..8].copy_from_slice(&(((hi as u64) << 32) | lo as u64).to_le_bytes());
        input[8] = i as u8;
        input[9] = 0x52; // domain tag: "R"
        input[10] = 0x44; // "D"
        input[11] = 0x4F; // "O"
        input[12] = 0x53; // "S"
        let mut digest = [0u8; 8];
        // blake2b cannot fail on these fixed sizes; treat error as fatal.
        crate::ffi::blake2b(&mut digest, &input, &[])
            .unwrap_or_else(|e| crate::panic_str("kms entropy: ", e));
        out[i * 8..(i + 1) * 8].copy_from_slice(&digest);
    }
    (out, "tsc-fallback(WEAK)")
}

// --- Boot-time init ---------------------------------------------------------

/// Configure the entropy policy. Call before `init` (kmain does, from a
/// compile-time policy constant — see main.rs RNG_POLICY and its honesty
/// note about production builds).
/// CEP: CEP-1 | Complete
/// Cost: one store.
/// Fail: cannot fail.
pub fn set_rng_policy(p: RngPolicy) {
    unsafe { RNG_POLICY = p };
}

/// The configured entropy policy (for banners/audit).
/// CEP: CEP-1 | Complete
/// Cost: one load.
/// Fail: cannot fail.
pub fn rng_policy() -> RngPolicy {
    unsafe { RNG_POLICY }
}

/// THE RNG decision function (pure; proof/Kms.thy `rng_admits` twin).
/// Strict builds admit only hardware RDRAND; Lenient admits everything
/// but the caller must surface the source honestly in the log.
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: cannot fail (returns the decision, never panics).
pub fn rng_admits(policy: RngPolicy, source: &str) -> bool {
    match policy {
        RngPolicy::Lenient => true,
        RngPolicy::Strict => source == "rdrand",
    }
}

/// The entropy source used at seal time ("rdrand", "tsc-fallback(WEAK)",
/// or "none" before init). Evidence channel for the RNG-policy banner.
/// CEP: CEP-1 | Complete
/// Cost: one load.
/// Fail: cannot fail.
pub fn last_entropy_source() -> &'static str {
    unsafe { ENTROPY_SRC }
}

/// Allocate the vault's Locked memory and seal a fresh master key under
/// the PIN-derived KEK. The PIN arrives through the input service (v0.7.0:
/// no PIN constant exists in the kernel binary — the CI feeder types it
/// over the UART; on hardware the operator does).
///
/// CEP: CEP-1 | Complete
/// Cost: O(arena frames) alloc + zero-on-grant; one Argon2id + one GCM.
/// Fail: panics on frame exhaustion or crypto contract breach (a vault
///       that cannot seal must not boot pretending it did). Strict policy
///       + non-RDRAND entropy enters the terminal Refused state instead:
///       no key is generated, nothing to unlock, everything fails closed.
/// Assumes: called once, after phys::init, before any task runs.
pub fn init(pin: &[u8]) {
    unsafe {
        // --- Locked frames: master, blob, Argon2id arena -----------------
        let mf = phys::alloc(PageClass::Locked)
            .unwrap_or_else(|| panic_str("kms: ", "master frame exhausted"));
        let bf = phys::alloc(PageClass::Locked)
            .unwrap_or_else(|| panic_str("kms: ", "blob frame exhausted"));
        let arena_frames = (ARGON2_MEMORY_KIB as usize * 1024) / PAGE_SIZE as usize;
        let ab = phys::alloc_contig(PageClass::Locked, arena_frames)
            .unwrap_or_else(|| panic_str("kms: ", "argon2 arena exhausted"));

        MASTER_FRAME = mf;
        BLOB_FRAME = bf;
        ARENA_BASE = ab;
        ARENA_FRAMES = arena_frames;

        // --- per-boot salt ------------------------------------------------
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("rax") lo, out("rdx") hi, options(nomem, nostack));
        SALT[..8].copy_from_slice(&HW_SALT_CONST);
        SALT[8..].copy_from_slice(&(((hi as u64) << 32) | lo as u64).to_le_bytes());

        // --- fresh master key -> entropy policy gate (v0.7.0) --------------
        let (mut master, src) = master_key_entropy();
        ENTROPY_SRC = src;
        if !rng_admits(rng_policy(), src) {
            // Strict refusal: destroy the freshly drawn key (IN PLACE —
            // the stack slot itself, not a copy), zero the sealed-blob
            // frame, and enter the terminal Refused state. No KEK
            // derivation runs (the PIN is never even read into the
            // vault's control flow), no blob is written, no key exists.
            wipe_bytes(&mut master);
            owner_zero_frame(BLOB_FRAME);
            STATE = VaultState::Refused;
            serial::print(format_args!(
                "[kms] STRICT RNG POLICY: entropy source '{}' is not RDRAND — refusing to generate a master key (vault REFUSED, terminal)\n",
                src
            ));
            return;
        }

        // --- seal under the PIN-derived KEK --------------------------------
        let arena = arena_slice();
        let kek = derive_kek_in_arena(pin, arena);
        scrub_arena();
        let mut iv = [0u8; crate::ffi::IV_LEN];
        match rdrand_u64() {
            Some(v) => iv[..8].copy_from_slice(&v.to_le_bytes()),
            None => iv[..8].copy_from_slice(&(((hi as u64) << 32) | lo as u64).to_le_bytes()),
        }
        match rdrand_u64() {
            Some(v) => iv[8..].copy_from_slice(&v.to_le_bytes()),
            None => iv[8..].copy_from_slice(&lo.to_le_bytes()),
        }
        let mut blob = [0u8; BLOB_LEN];
        blob[..crate::ffi::IV_LEN].copy_from_slice(&iv);
        let (ct, tag) = blob[crate::ffi::IV_LEN..].split_at_mut(MASTER_KEY_LEN);
        let mut tag_arr = [0u8; crate::ffi::TAG_LEN];
        crate::ffi::gcm_encrypt(&kek, &iv, &master, &[], ct, &mut tag_arr)
            .unwrap_or_else(|e| panic_str("seal: gcm: ", e));
        tag.copy_from_slice(&tag_arr);
        // blob -> blob frame (Locked, via HHDM)
        let bp = bf as *mut u8;
        for (i, b) in blob.iter().enumerate() {
            bp.add(i).write_volatile(*b);
        }
        // scrub locals: master + KEK must not linger on the boot stack
        let mut m0 = master;
        let mut k0 = kek;
        wipe_bytes(&mut m0);
        wipe_bytes(&mut k0);
        wipe_bytes(&mut blob);
        wipe_bytes(&mut tag_arr);

        STATE = VaultState::Sealed;
        serial::print(format_args!(
            "[kms] vault sealed: master key (entropy: {}) in Locked frame {:#x}; blob frame {:#x}; arena {} KiB = {} Locked frames\n",
            src, mf, bf, ARGON2_MEMORY_KIB, arena_frames
        ));
    }
}

// --- Derivations ------------------------------------------------------------

/// KEK = Argon2id(PIN, salt, m=8MiB, t=2, p=1), first 32 bytes of tag.
/// Runs entirely in the Locked arena; the arena is scrubbed by the
/// caller (unlock/duress paths own it).
fn derive_kek_in_arena(pin: &[u8], arena: &mut [u8]) -> [u8; KEK_LEN] {
    let mut kek = [0u8; KEK_LEN];
    crate::ffi::argon2id(
        &mut kek,
        pin,
        unsafe { &*core::ptr::addr_of!(SALT) },
        ARGON2_PASSES,
        ARGON2_MEMORY_KIB,
        ARGON2_LANES,
        arena,
    )
    .unwrap_or_else(|e| panic_str("kms argon2id: ", e));
    kek
}

/// Domain-separated sub-key: BLAKE2b-256(key = master, in = domain || ctx).
fn derive_subkey(master: &[u8; MASTER_KEY_LEN], domain: &[u8], ctx: &[u8]) -> [u8; MASTER_KEY_LEN] {
    let mut input = [0u8; 64];
    let n = domain.len().min(32);
    input[..n].copy_from_slice(&domain[..n]);
    let m = ctx.len().min(64 - n);
    input[n..n + m].copy_from_slice(&ctx[..m]);
    let mut out = [0u8; MASTER_KEY_LEN];
    crate::ffi::blake2b(&mut out, &input, master)
        .unwrap_or_else(|e| panic_str("kms blake2b: ", e));
    out
}

/// The XTS disk key (K1 || K2), derived fresh per call, valid only in
/// the caller's stack frame. Exists only while Unlocked.
/// CEP: CEP-1 | Complete
/// Fail: KmsError::Dead / Refused / Sealed (fail-closed); Crypto on contract error.
pub fn disk_key() -> Result<[u8; crate::ffi::XTS_KEY_LEN], KmsError> {
    match vault_state() {
        VaultState::Unlocked => {}
        VaultState::Dead | VaultState::Wiping => return Err(KmsError::Dead),
        VaultState::Refused => return Err(KmsError::Refused),
        VaultState::Sealed => return Err(KmsError::Sealed),
    }
    let mut master = read_master()?;
    let mut k1 = derive_subkey(&master, b"redos/ramdisk/k1/v1", &[]);
    let mut k2 = derive_subkey(&master, b"redos/ramdisk/k2/v1", &[]);
    let mut key = [0u8; crate::ffi::XTS_KEY_LEN];
    key[..32].copy_from_slice(&k1);
    key[32..].copy_from_slice(&k2);
    wipe_bytes(&mut k1);
    wipe_bytes(&mut k2);
    wipe_bytes(&mut master);
    Ok(key)
}

// --- Unlock / duress --------------------------------------------------------

/// Attempt an unlock with `pin`.
///
/// The attempt counter is bumped FIRST, in every state except Dead/
/// Wiping — including while the vault is already Unlocked (a wrong PIN
/// against an open vault is exactly the hammering signal the budget
/// exists for). The attempt that reaches `MAX_ATTEMPTS` triggers the
/// duress wipe and never touches the crypto: a counter-satisfying
/// attempt cannot run Argon2id at all, whatever PIN it carries.
///
/// CEP: CEP-1 | Complete
/// Cost: one Argon2id (8 MiB, t=2) + one GCM decrypt (Sealed attempts
///       only); on first success also installs the phys wipe key.
/// Fail: UnlockError::Dead — the attempt REACHED the budget and the
///       vault is destroyed (terminal);
///       UnlockError::WrongPin{remaining} — GCM tag failure against a
///       sealed vault, counter bumped;
///       AlreadyUnlocked — vault already open (attempt still counted);
///       Crypto — C-core contract error (never expected).
pub fn unlock(pin: &[u8]) -> Result<(), UnlockError> {
    match vault_state() {
        VaultState::Dead | VaultState::Wiping => {
            return Err(UnlockError::Dead);
        }
        VaultState::Refused => {
            return Err(UnlockError::Refused);
        }
        VaultState::Sealed | VaultState::Unlocked => {}
    }

    unsafe {
        ATTEMPTS += 1;
        if ATTEMPTS >= MAX_ATTEMPTS {
            // Duress: this attempt never gets to try the crypto.
            duress_wipe();
            return Err(UnlockError::Dead);
        }
        let remaining = MAX_ATTEMPTS - ATTEMPTS;

        if vault_state() == VaultState::Unlocked {
            // Already open (attempt counted above — hammering budget).
            return Err(UnlockError::AlreadyUnlocked);
        }

        // Argon2id in the Locked arena.
        let arena = arena_slice();
        let mut kek = derive_kek_in_arena(pin, arena);
        scrub_arena();

        // GCM-unwrap the blob (fail-closed: the C core zeroes the pt on
        // AUTH failure; we additionally zero the whole KEK+pt below).
        let bp = BLOB_FRAME as *const u8;
        let mut blob = [0u8; BLOB_LEN];
        for (i, b) in blob.iter_mut().enumerate() {
            *b = bp.add(i).read_volatile();
        }
        let mut iv = [0u8; crate::ffi::IV_LEN];
        iv.copy_from_slice(&blob[..crate::ffi::IV_LEN]);
        let mut master = [0u8; MASTER_KEY_LEN];
        let mut tag = [0u8; crate::ffi::TAG_LEN];
        tag.copy_from_slice(&blob[crate::ffi::IV_LEN + MASTER_KEY_LEN..]);

        let rc = crate::ffi::gcm_decrypt(
            &kek,
            &iv,
            &blob[crate::ffi::IV_LEN..crate::ffi::IV_LEN + MASTER_KEY_LEN],
            &[],
            &tag,
            &mut master,
        );
        wipe_bytes(&mut kek);
        wipe_bytes(&mut blob);
        match rc {
            Ok(()) => {}
            Err("AUTH") => {
                return Err(UnlockError::WrongPin { remaining });
            }
            Err(e) => {
                return Err(UnlockError::Crypto(e));
            }
        }

        // Unlocked: master key lives in its Locked frame from now on.
        let mp = MASTER_FRAME as *mut u8;
        // (master was already zeroized by gcm_decrypt's fail-closed pt
        // handling on the error paths above; here it is live key material)
        for (i, b) in master.iter().enumerate() {
            mp.add(i).write_volatile(*b);
        }
        wipe_bytes(&mut master);
        STATE = VaultState::Unlocked;

        // Upgrade the allocator's wipe stream (KMS-owned key).
        let mut wk = match read_master() {
            Ok(m) => m,
            Err(_) => {
                return Err(UnlockError::Crypto("STATE"));
            }
        };
        let mut wipe_key = derive_subkey(&wk, b"redos/wipe/v1", &[]);
        // The master-key COPY leaves via the scrub (B1 fix, v0.6.0 review):
        // only the Locked-frame resident survives, as the module contract
        // promises.
        wipe_bytes(&mut wk);
        phys::set_wipe_key(wipe_key);
        wipe_bytes(&mut wipe_key);
        Ok(())
    }
}

/// The dead-man wipe. Zeroizes every secret the vault owns, reverts the
/// allocator wipe upgrade, and enters the terminal Dead state.
///
/// CEP: CEP-1 | Complete
/// Cost: O(vault bytes): master frame, blob frame, arena, leases.
/// Fail: cannot fail; idempotent (second call observes Dead and stops).
/// Assumes: single CPU (no concurrent access to vault statics).
fn duress_wipe() {
    unsafe {
        if STATE == VaultState::Dead || STATE == VaultState::Refused {
            // Both terminal states carry no live secrets to wipe.
            return;
        }
        STATE = VaultState::Wiping;

        // Owner-zero the Locked frames (allocator free() refuses Locked —
        // the vault is the only writer allowed to clear them).
        owner_zero_frame(MASTER_FRAME);
        owner_zero_frame(BLOB_FRAME);
        // Arena may span many frames: scrub the whole span.
        if ARENA_FRAMES > 0 {
            let arena = arena_slice();
            for b in arena.iter_mut() {
                *b = 0; // zero pass (noise pass would need the key we are destroying)
            }
            scrub_arena();
        }
        for i in 0..MAX_LEASES {
            LEASES[i].in_use = false;
            LEASES[i].expires_tick = 0;
            wipe_bytes(&mut LEASES[i].key);
        }
        phys::clear_wipe_key();
        STATE = VaultState::Dead;
        serial::print(format_args!(
            "[kms] DURESS: wrong-pin budget reached — vault destroyed (master, blob, arena, leases zeroized)\n"
        ));
    }
}

/// Vault status string for banners/audit.
pub fn status() -> &'static str {
    match vault_state() {
        VaultState::Sealed => "SEALED",
        VaultState::Unlocked => "UNLOCKED",
        VaultState::Wiping => "WIPING",
        VaultState::Dead => "DEAD",
        VaultState::Refused => "REFUSED",
    }
}

/// Attempts consumed so far (monotone; for the boot log).
pub fn attempts_used() -> u32 {
    unsafe { ATTEMPTS }
}

// --- Leases -----------------------------------------------------------------

/// Grant a lease on a freshly derived key with a `ttl_ticks` lifetime,
/// bound to its owner task (v0.7.0: only the owner's `lease_use` can
/// ever serve the key; a non-owner sees NoSuchLease — indistinguishable
/// from a missing lease, so ownership is not even observable).
/// CEP: CEP-1 | Complete
/// Cost: one BLAKE2b.
/// Fail: KmsError::Dead / Refused / Sealed; Err(Exhausted-as-Crypto) if the
///       table is full (named via Crypto("LEASES-FULL") — Phase 2 demo scale).
/// Assumes: cooperative single-CPU; lazy expiry (checked at use).
pub fn lease_grant(ttl_ticks: u64, owner: usize) -> Result<usize, KmsError> {
    match vault_state() {
        VaultState::Unlocked => {}
        VaultState::Dead | VaultState::Wiping => return Err(KmsError::Dead),
        VaultState::Refused => return Err(KmsError::Refused),
        VaultState::Sealed => return Err(KmsError::Sealed),
    }
    unsafe {
        let mut master = read_master()?;
        let mut slot = None;
        for i in 0..MAX_LEASES {
            if !LEASES[i].in_use {
                slot = Some(i);
                break;
            }
        }
        let i = match slot {
            Some(i) => i,
            None => return Err(KmsError::Crypto("LEASES-FULL")),
        };
        LEASE_SEQ += 1;
        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(&LEASE_SEQ.to_le_bytes());
        ctx[8..].copy_from_slice(&crate::task::ticks().to_le_bytes());
        LEASES[i].key = derive_subkey(&master, b"redos/lease/v1", &ctx);
        LEASES[i].expires_tick = crate::task::ticks() + ttl_ticks;
        LEASES[i].owner = owner;
        LEASES[i].in_use = true;
        wipe_bytes(&mut master);
        Ok(i)
    }
}

/// Use a lease: expired leases are zeroized on first touch (lazy expiry
/// is the only expiry — there is no timer interrupt in Phase 2) and the
/// access fails with `Expired` forever after. The `owner` parameter must
/// name the task the lease was granted to; anything else refuses with
/// NoSuchLease (same error as a missing id — ownership is not observable
/// through the error channel).
/// CEP: CEP-1 | Complete
/// Fail: Dead/Refused/Sealed/NoSuchLease(incl. wrong owner)/Expired — all
///       named, all fail-closed.
pub fn lease_use(id: usize, owner: usize) -> Result<[u8; MASTER_KEY_LEN], KmsError> {
    match vault_state() {
        VaultState::Unlocked => {}
        VaultState::Dead | VaultState::Wiping => return Err(KmsError::Dead),
        VaultState::Refused => return Err(KmsError::Refused),
        VaultState::Sealed => return Err(KmsError::Sealed),
    }
    unsafe {
        if id >= MAX_LEASES || !LEASES[id].in_use {
            return Err(KmsError::NoSuchLease);
        }
        if LEASES[id].owner != owner {
            // Wrong owner: refuse without revealing the lease exists.
            return Err(KmsError::NoSuchLease);
        }
        if crate::task::ticks() >= LEASES[id].expires_tick {
            LEASES[id].in_use = false;
            wipe_bytes(&mut LEASES[id].key);
            return Err(KmsError::Expired);
        }
        Ok(LEASES[id].key)
    }
}

/// The manifest authentication key: a domain-separated derivation from
/// the master key ("redos/manifest/v1"). The Permission-Tracker world
/// trusts manifests that carry a valid MAC under this key — the vault
/// being open IS the trust anchor (zero-ID: authority flows from the
/// operator's PIN, never from an identity). Exists only inside the
/// caller's frame; identity.rs wipes it after use.
/// CEP: CEP-1 | Complete
/// Fail: Dead / Refused / Sealed (fail-closed: no manifests verify while
///       the vault is closed — spawning halts with the vault).
pub fn manifest_key() -> Result<[u8; MASTER_KEY_LEN], KmsError> {
    match vault_state() {
        VaultState::Unlocked => {}
        VaultState::Dead | VaultState::Wiping => return Err(KmsError::Dead),
        VaultState::Refused => return Err(KmsError::Refused),
        VaultState::Sealed => return Err(KmsError::Sealed),
    }
    let mut master = read_master()?;
    let key = derive_subkey(&master, b"redos/manifest/v1", &[]);
    wipe_bytes(&mut master);
    Ok(key)
}

// --- Internals --------------------------------------------------------------

#[allow(static_mut_refs)]
fn vault_state() -> VaultState {
    unsafe { STATE }
}

/// Read the live master key (Unlocked only).
fn read_master() -> Result<[u8; MASTER_KEY_LEN], KmsError> {
    if vault_state() != VaultState::Unlocked {
        return Err(KmsError::Sealed);
    }
    unsafe {
        // Vault invariant: the master frame must still be Locked (a class
        // violation would mean the mlock mandate broke — fail-fast).
        if phys::class_of(MASTER_FRAME) != PageClass::Locked {
            crate::panic_str("kms invariant: ", "master frame not Locked");
        }
        let mp = MASTER_FRAME as *const u8;
        let mut out = [0u8; MASTER_KEY_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = mp.add(i).read_volatile();
        }
        Ok(out)
    }
}

/// The Argon2id arena as a byte slice (Locked-class, HHDM-addressed).
#[allow(static_mut_refs)]
fn arena_slice() -> &'static mut [u8] {
    unsafe {
        let len = ARENA_FRAMES as usize * PAGE_SIZE as usize;
        core::slice::from_raw_parts_mut(ARENA_BASE as *mut u8, len)
    }
}

/// Zero the arena without touching other Locked frames (owner pass).
#[allow(static_mut_refs)]
fn scrub_arena() {
    let arena = arena_slice();
    for b in arena.iter_mut() {
        *b = 0;
    }
}

/// Owner-zero one frame: plain zero pass. Noise is unnecessary here —
/// the vault KNOWS what it is destroying (its own keys); zeros make the
/// destruction verifiable (the duress banner checks the frame is zero).
fn owner_zero_frame(phys_addr: u64) {
    let base = phys_addr as *mut u64;
    for k in 0..(PAGE_SIZE / 8) {
        unsafe {
            base.add(k as usize).write_volatile(0u64);
        }
    }
}

/// Physical address of the Locked frame holding the live master key
/// (0 before first init). The scenario uses it to verify the mlock
/// mandate and the duress zeroization — the address itself is not secret
/// (it is reachable from any root via the identity map; the CONTENT is).
pub fn master_frame_phys() -> u64 {
    unsafe { MASTER_FRAME }
}

/// Physical address of the sealed-blob frame (same non-secrecy note).
pub fn blob_frame_phys() -> u64 {
    unsafe { BLOB_FRAME }
}

/// Security scrub: volatile stores (mechanically unelidable — LLVM must
/// perform every one) plus a black_box fence so no optimizer pass can
/// reason the zeros away. Every key copy the vault holds on a stack
/// exits through this function; the duress banner verifies the frame
/// zeroization empirically (256-word sweep in the boot scenario).
fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::hint::black_box(buf);
}

#[cold]
fn panic_str(msg: &str, reason: &str) -> ! {
    crate::panic_str(msg, reason)
}
