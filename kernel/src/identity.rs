//! RedOS kernel — Zero-ID identity (v0.7.0, Pillar 1).
//!
//! Authority without identity: there are no usernames, no UIDs, no
//! certificate chains. A program's identity is the CONTENT it runs
//! (BLAKE2b-256 over the entry image), its authority is what an
//! operator-approved manifest requested, and every runtime grant flows
//! through an interactive prompt to the operator — recorded in the
//! Permission Tracker, enforced by the capability system. The trust
//! anchor is the RAM-only vault: manifests carry a MAC under a
//! vault-derived key, so a sealed/dead vault refuses every spawn
//! (fail-closed); the operator's PIN is the only root of trust and it
//! never exists outside the input service and the vault.
//!
//! The three pieces:
//!
//! * **Manifest schema** (64 bytes): sandbox profile, requested
//!   authorities, lease terms, the binary content hash, and a keyed-
//!   BLAKE2b MAC over all of it. `spawn_from_manifest` refuses a bad MAC
//!   (forged manifest), a bad hash (substituted binary), and refuses
//!   everything when the vault is closed.
//! * **Sandbox spawner**: fresh address-space root per spawn, the
//!   program's code window mapped READ-ONLY at DEMO_BASE (the spawn-
//!   granted W^X surface), and exactly one default grant — SEND/RECV on
//!   the prompt endpoint — so a sandboxed task can *ask*, and do
//!   nothing else (default-deny).
//! * **Permission Tracker**: an append-only decision ledger. Every
//!   grant/denial/expiry/revocation is recorded BEFORE the corresponding
//!   authority exists — universally: the spawn default grant (record,
//!   then cap mint), the lease grant (record, then KMS lease; a KMS
//!   failure appends a superseding Denied), the disk grant (record, and
//!   the record IS the authority the use-time check reads), and every
//!   refusal (recorded, never silent). The mechanical direction of
//!   Ident.thy's tracked invariant: a live authority always has a
//!   Granted record behind it.
//!
//! Phase-2 model notes (honesty, mirroring CEP style elsewhere):
//! 1. *In-kernel programs.* The manifest binds an entry FUNCTION's bytes;
//!    real ELF user binaries need ring 3 + a loader (fast-path milestone,
//!    v0.8.0). The refusal mechanism (MAC/hash checks before spawn) is
//!    the deliverable and is exercised with real refusal scenarios.
//! 2. *Caller-supplied task index.* Lease owner and disk authority take
//!    the caller's task index as a parameter; a ring-3 boundary makes it
//!    structural (v0.8.0). The binding logic itself is enforced and
//!    tested here (lease theft refuses; authority denial refuses).
//! 3. *Kernel-image text stays RW in the low identity map* (2 MiB pages,
//!    bring-up simplicity). The sandbox window at DEMO_BASE is the
//!    spawner's RO mapping; image-wide W^X is a v0.8.0 paging item.
//!
//! CEP: CEP-1 | Complete (Phase 2 scope: one sandbox slot, 3 authorities,
//!       24 tracker records — demo scale, statically bounded)
//! Cost: manifest MAC O(1) BLAKE2b; spawn O(root build) + O(1) mints;
//!       tracker O(MAX_RECORDS) scans.
//! Fail: every path returns named errors; refusals are recorded, never
//!       silent. The service panics only on kernel-contract breaches.
//! Assumes: single CPU, cooperative scheduling; the input service is
//!          single-consumer (prompts are sequenced by the scenario).

use crate::cap::{self, RW};
use crate::ffi;
use crate::input::{self, Echo};
use crate::ipc::{self, IpcRecvError, IpcSendError};
use crate::kms;
use crate::mm::idt;
use crate::mm::pagemap;
use crate::mm::phys::PAGE_SIZE;
use crate::serial;
use crate::task;
use core::sync::atomic::{AtomicUsize, Ordering};

// --- Authority space ---------------------------------------------------------

/// Authority bit: may hold a KMS lease (lease-scoped key authority).
pub const AUTH_LEASE: u32 = 1;
/// Authority bit: may perform RAM-disk I/O (checked at use time).
pub const AUTH_DISK: u32 = 2;
/// Authority bit: the default grant — the prompt endpoint itself.
pub const AUTH_PROMPT: u32 = 4;

// --- Manifest schema ----------------------------------------------------------

/// Full manifest record: prefix (48) || MAC (16). The on-wire size; the
/// struct is the parsed form (never heap-allocated, always by-value).
#[allow(dead_code)]
pub const MANIFEST_LEN: usize = 64;
/// MACed prefix layout:
///   [0..4] magic "RMAN" | [4..6] version | [6] profile | [7] flags
///   [8..12] requested authorities | [12..16] max lease TTL (ticks)
///   [16..48] binary content hash (BLAKE2b-256)
pub const PREFIX_LEN: usize = 48;
/// MAC length (keyed BLAKE2b, truncated to 128 bits).
pub const MAC_LEN: usize = 16;
pub const MANIFEST_MAGIC: [u8; 4] = *b"RMAN";
pub const MANIFEST_VERSION: u16 = 1;
/// Sandbox profiles. Strict caps lease TTLs (see lease_ttl_admitted).
pub const PROFILE_STD: u8 = 0;
pub const PROFILE_STRICT: u8 = 1;

/// Strict-profile lease ceiling (scheduler ticks). A request beyond this
/// is denied MECHANICALLY — no operator prompt can override it (math
/// over trust: policy caps are kernel policy, not operator mood).
pub const STRICT_LEASE_TTL_MAX: u64 = 64;

/// THE TTL policy function (pure; Ident.thy `ttl_admitted` twin).
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: cannot fail (returns the decision).
pub fn lease_ttl_admitted(profile: u8, ttl: u64) -> bool {
    if profile == PROFILE_STRICT {
        ttl <= STRICT_LEASE_TTL_MAX
    } else {
        true
    }
}

/// A vouching manifest (see module docs + PREFIX_LEN layout).
#[derive(Clone, Copy)]
pub struct Manifest {
    /// Sandbox profile (PROFILE_*).
    pub profile: u8,
    /// Requests the lease authority (AUTH_LEASE).
    pub req_lease: bool,
    /// Requests the disk authority (AUTH_DISK).
    pub req_disk: bool,
    /// Requested maximum lease TTL in scheduler ticks (u32 on the wire).
    pub lease_ttl: u64,
    /// BLAKE2b-256 content hash of the entry program.
    pub binary_hash: [u8; 32],
    /// Resolved entry address (in-kernel program; NOT MACed — the hash
    /// binds the content, the address is the loader's resolved target of
    /// that content in the Phase-2 model).
    pub entry: u64,
    /// Keyed-BLAKE2b MAC over the prefix (set by `sign`).
    pub mac: [u8; MAC_LEN],
}

impl Manifest {
    /// Serialize the MACed prefix.
    fn encode_prefix(&self, out: &mut [u8; PREFIX_LEN]) {
        out[0..4].copy_from_slice(&MANIFEST_MAGIC);
        out[4..6].copy_from_slice(&MANIFEST_VERSION.to_le_bytes());
        out[6] = self.profile;
        out[7] = 0; // flags: reserved, must be zero
        let mut caps = 0u32;
        if self.req_lease {
            caps |= 1;
        }
        if self.req_disk {
            caps |= 2;
        }
        out[8..12].copy_from_slice(&caps.to_le_bytes());
        out[12..16].copy_from_slice(&(self.lease_ttl as u32).to_le_bytes());
        out[16..48].copy_from_slice(&self.binary_hash);
    }

    /// Compute and install the manifest MAC under the vault-derived key.
    /// CEP: CEP-1 | Complete
    /// Cost: one BLAKE2b.
    /// Fail: panics when the vault is closed — only the identity service
    ///       signs manifests, and it runs strictly after the unlock.
    pub fn sign(&mut self) {
        let mut key = kms::manifest_key()
            .unwrap_or_else(|e| panic_str("manifest sign: vault closed: ", kms_err(e)));
        let mut prefix = [0u8; PREFIX_LEN];
        self.encode_prefix(&mut prefix);
        ffi::blake2b(&mut self.mac, &prefix, &key)
            .unwrap_or_else(|e| panic_str("manifest sign: blake2b: ", e));
        scrub(&mut key);
    }
}

/// Program identity: BLAKE2b-256 over (entry address || first 64 code
/// bytes). The probe length is fixed by policy; reading 64 bytes of
/// kernel text cannot fault (the image is contiguous and mapped — see
/// module docs note 1).
/// CEP: CEP-1 | Complete
/// Cost: one BLAKE2b over 72 bytes.
/// Fail: panics on a BLAKE2b contract error (never expected).
pub fn fn_identity_hash(entry_addr: u64) -> [u8; 32] {
    const PROBE: usize = 64;
    let mut input = [0u8; 8 + PROBE];
    input[..8].copy_from_slice(&entry_addr.to_le_bytes());
    let code = unsafe { core::slice::from_raw_parts(entry_addr as *const u8, PROBE) };
    input[8..].copy_from_slice(code);
    let mut out = [0u8; 32];
    ffi::blake2b(&mut out, &input, &[])
        .unwrap_or_else(|e| panic_str("identity hash: blake2b: ", e));
    out
}

/// Sandbox spawner refusals (named; the CI log prints them verbatim).
#[derive(Debug)]
pub enum SpawnError {
    /// The vault is closed: no manifest key, no spawn (fail-closed).
    VaultClosed,
    /// The MAC did not verify — the manifest is forged or corrupted.
    MacMismatch,
    /// The manifest's entry address is not readable kernel text — it
    /// cannot name a program (named refusal instead of a fault).
    BadEntry,
    /// The binary's content hash differs from the manifest's binding —
    /// the roadmap exit criterion "spawner refuses hash mismatch".
    HashMismatch,
    /// Unknown sandbox profile byte.
    Profile,
    /// Address-space construction failed (frame exhaustion).
    Paging,
    /// Default-grant mint failed (fresh tables are empty — never expected).
    DefaultGrant(#[allow(dead_code)] &'static str),
    /// C-core contract error (never expected).
    Crypto(#[allow(dead_code)] &'static str),
}

/// The sandbox code window (PML4[224] region, distinct from PRIV_BASE /
/// PRIV_ALT): the spawner maps the entry program's page here READ-ONLY
/// in the spawned task's root. The sandbox probes this window for the
/// W^X evidence banner.
pub const DEMO_BASE: u64 = 0x0000_7100_0000_0000;

/// Spawn a task from an operator-vouched manifest.
///
/// Refusal order: MAC first (the MAC covers the hash — a forged manifest
/// must not even reach the hash comparison), then entry readability
/// (an unmappable address cannot be a kernel program), then the content
/// hash, then profile validity, then construction. On success the task
/// exists with a fresh root, an RO code window, and exactly one
/// authority: the prompt endpoint (recorded in the tracker BEFORE the
/// cap is minted).
///
/// Refusal inertness is exact for the VERIFICATION refusals (MAC, hash,
/// profile): nothing is constructed, so nothing can leak. The
/// CONSTRUCTION refusals are the honest residual: Paging leaves the
/// fresh root's frames allocated (they are wiped-or-parked by the
/// allocator's protocol, never handed out with stale content), and
/// DefaultGrant leaves a spawned task with zero capabilities (a
/// default-deny task that can ask for nothing) — both are unreachable
/// in any correctly provisioned scenario and neither grants authority.
///
/// CEP: CEP-1 | Complete
/// Cost: one BLAKE2b (MAC) + one BLAKE2b (hash) + O(1) paging + 1 mint.
/// Fail: named SpawnError for every refusal.
/// Assumes: called after the vault is Unlocked; single CPU.
pub fn spawn_from_manifest(m: &Manifest) -> Result<usize, SpawnError> {
    // 1. MAC under the vault key (fail-closed on a closed vault).
    let mut key = kms::manifest_key().map_err(|_| SpawnError::VaultClosed)?;
    let mut prefix = [0u8; PREFIX_LEN];
    m.encode_prefix(&mut prefix);
    let mut mac = [0u8; MAC_LEN];
    let mac_rc = ffi::blake2b(&mut mac, &prefix, &key);
    scrub(&mut key);
    mac_rc.map_err(SpawnError::Crypto)?;
    let mut diff = 0u8;
    for i in 0..MAC_LEN {
        diff |= mac[i] ^ m.mac[i];
    }
    if diff != 0 {
        return Err(SpawnError::MacMismatch);
    }

    // 2. Entry readability: the manifest names an in-kernel program; a
    //    MAC-valid manifest pointing at unmapped/canonical garbage gets
    //    a NAMED refusal instead of a fault inside the hasher.
    if idt::probe_read(m.entry).is_none() {
        return Err(SpawnError::BadEntry);
    }

    // 3. Content binding: the binary as it EXISTS must hash to what the
    //    manifest vouched for (substitution refuses here).
    let actual = fn_identity_hash(m.entry);
    if actual != m.binary_hash {
        return Err(SpawnError::HashMismatch);
    }

    // 4. Profile validity.
    if m.profile != PROFILE_STD && m.profile != PROFILE_STRICT {
        return Err(SpawnError::Profile);
    }

    // 5. Fresh address space; code window RO (spawn-granted W^X surface).
    let root = pagemap::new_task_root().map_err(|_| SpawnError::Paging)?;
    let code_page = m.entry & !(PAGE_SIZE as u64 - 1);
    pagemap::map_page(root, DEMO_BASE, code_page, false).map_err(|_| SpawnError::Paging)?;

    // 6. Spawn and install the root before the task ever runs.
    let d = task::spawn_at(m.entry, 0);
    task::tasks()[d].cr3 = root;

    // 7. Default grant: RECORD FIRST, then mint (no cap without record —
    //    the mechanical direction of Ident.thy's tracked invariant).
    append_record(Record {
        task: d,
        auth: AUTH_PROMPT,
        scope: Scope::Session,
        decision: Decision::Granted,
        at_tick: task::ticks(),
        note: "default-grant",
    });
    let ep = cfg().ep_prompt;
    let slot = cap::table_of(d)
        .mint(ep, RW)
        .map_err(SpawnError::DefaultGrant)?;
    TASK_D_CAP.store(slot, Ordering::Relaxed);

    Ok(d)
}

// --- Permission Tracker -------------------------------------------------------

/// Grant scope: lives with the task (Session) or on a KMS lease (Lease).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Dies with the task (task_exit records Revoked + clears the table).
    Session,
    /// Bound to a KMS lease id (owner + tick-TTL enforced by the KMS).
    Lease(usize),
}

/// Tracker decisions (append-only: a later record supersedes an earlier
/// one for the same (task, auth) — liveness is the LATEST decision).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Authority granted (by operator prompt or bootstrap).
    Granted,
    /// Authority refused (operator or mechanical policy cap).
    Denied,
    /// Session-scoped authority ended with the task.
    Revoked,
    /// Lease-scoped authority expired (lazy expiry observed).
    Expired,
}

/// One tracker record. `scope`/`at_tick`/`note` are the evidentiary
/// payload of the ledger — the boot audit summarizes by decision counts;
/// the fields are what the v1.0 capability shell/REPL (roadmap Phase 5)
/// will surface for human inspection. Kept in the record for that
/// contract (allow: they are data, not dead logic).
#[derive(Clone, Copy)]
pub struct Record {
    pub task: usize,
    pub auth: u32,
    #[allow(dead_code)] // evidence payload (see struct docs)
    pub scope: Scope,
    pub decision: Decision,
    #[allow(dead_code)] // evidence payload (see struct docs)
    pub at_tick: u64,
    #[allow(dead_code)] // evidence payload (see struct docs)
    pub note: &'static str,
}

/// Tracker capacity (demo scale; full ledger = named refusal).
pub const MAX_RECORDS: usize = 24;

static mut RECORDS: [Record; MAX_RECORDS] = [Record {
    task: usize::MAX,
    auth: 0,
    scope: Scope::Session,
    decision: Decision::Denied,
    at_tick: 0,
    note: "",
}; MAX_RECORDS];
static mut RECORD_COUNT: usize = 0;

/// Append one record. CEP: CEP-1 | Complete
/// Cost: O(1). Fail: panics on tracker exhaustion (the grant paths call
/// this BEFORE minting — a full tracker must never become silent
/// authority; fail-fast is the conservative direction).
fn append_record(r: Record) {
    unsafe {
        if RECORD_COUNT >= MAX_RECORDS {
            panic_str("identity: ", "tracker exhausted");
        }
        RECORDS[RECORD_COUNT] = r;
        RECORD_COUNT += 1;
    }
}

/// Whether `task` currently holds `auth`: the LATEST record for
/// (task, auth) decides — Granted means live, anything after it
/// (Denied/Revoked/Expired) means not. This is the tracker's POLICY
/// plane; the disk path enforces it at use time (ramdisk.rs).
/// CEP: CEP-1 | Complete
/// Cost: O(RECORD_COUNT) scan.
/// Fail: cannot fail (no records = no authority).
#[allow(static_mut_refs)]
pub fn has_authority(task: usize, auth: u32) -> bool {
    unsafe {
        let mut live = false;
        for i in 0..RECORD_COUNT {
            let r = &RECORDS[i];
            if r.task == task && r.auth == auth {
                live = r.decision == Decision::Granted;
            }
        }
        live
    }
}

/// Total records appended so far (audit evidence).
/// CEP: CEP-1 | Complete
/// Cost: one load. Fail: cannot fail.
#[allow(static_mut_refs)]
pub fn record_count() -> usize {
    unsafe { RECORD_COUNT }
}

/// Count records for one task by decision (audit evidence line).
#[allow(static_mut_refs)]
pub fn count_for_task(task: usize) -> (usize, usize, usize, usize) {
    unsafe {
        let (mut g, mut d, mut rv, mut ex) = (0, 0, 0, 0);
        for i in 0..RECORD_COUNT {
            let r = &RECORDS[i];
            if r.task != task {
                continue;
            }
            match r.decision {
                Decision::Granted => g += 1,
                Decision::Denied => d += 1,
                Decision::Revoked => rv += 1,
                Decision::Expired => ex += 1,
            }
        }
        (g, d, rv, ex)
    }
}

/// kmain's bootstrap grant (pre-tracker authorities the scenario needs:
/// the vault client C may perform disk I/O). Recorded like any other
/// grant — nothing is above the ledger.
/// CEP: CEP-1 | Complete
/// Cost: O(1). Fail: panics on tracker exhaustion.
pub fn bootstrap_grant(task_idx: usize, auth: u32) {
    append_record(Record {
        task: task_idx,
        auth,
        scope: Scope::Session,
        decision: Decision::Granted,
        at_tick: task::ticks(),
        note: "bootstrap",
    });
}

/// Session death hook — called by `task::task_exit` BEFORE the table
/// clear. Appends Revoked for every LIVE granted authority of the dying
/// task (Expired/Denied authorities stay as they are — the ledger
/// records what happened, not what didn't).
/// CEP: CEP-1 | Complete
/// Cost: O(authorities × RECORD_COUNT).
/// Fail: panics on tracker exhaustion (same contract as append_record).
pub fn on_task_exit(task_idx: usize) {
    for auth in [AUTH_LEASE, AUTH_DISK, AUTH_PROMPT] {
        if has_authority(task_idx, auth) {
            append_record(Record {
                task: task_idx,
                auth,
                scope: Scope::Session,
                decision: Decision::Revoked,
                at_tick: task::ticks(),
                note: "session-death",
            });
        }
    }
}

/// Record a lease expiry observation (the owner reports its lease died —
/// lazy expiry is KMS-side; the ledger mirrors it for the audit).
/// CEP: CEP-1 | Complete
/// Cost: O(1). Fail: panics on tracker exhaustion.
pub fn note_lease_expired(task_idx: usize, lease_id: usize) {
    append_record(Record {
        task: task_idx,
        auth: AUTH_LEASE,
        scope: Scope::Lease(lease_id),
        decision: Decision::Expired,
        at_tick: task::ticks(),
        note: "lease-expired",
    });
}

// --- Service configuration ----------------------------------------------------

/// Everything kmain wires up before the identity service runs.
#[derive(Clone, Copy)]
pub struct Config {
    /// The prompt endpoint index (requests + replies).
    pub ep_prompt: usize,
    /// The completion endpoint index (C's open signal + S's done signal).
    pub ep_done: usize,
    /// S's capability slot for ep_prompt (RW).
    pub cap_prompt: usize,
    /// S's capability slot for ep_done (RW).
    pub cap_done: usize,
    /// The demo program's entry address (manifest target).
    pub demo_entry: u64,
    /// A DIFFERENT kernel function's address — the decoy hash source for
    /// the hash-refusal scenario (manifest vouches for decoy content,
    /// spawner is handed the real entry: mismatch must refuse).
    pub decoy_entry: u64,
    /// Embedded ELF user programs (v0.8.0): the fast-path server, the
    /// fast-path client, and the intentional-fault containment demo.
    /// Built by the Makefile from usr/ and embedded via include_bytes!.
    pub elf_srv: &'static [u8],
    pub elf_cli: &'static [u8],
    pub elf_faulty: &'static [u8],
}

static mut CFG: Option<Config> = None;
/// The spawned sandbox's task slot (0 until a spawn succeeds).
static TASK_D: AtomicUsize = AtomicUsize::new(0);
/// The sandbox's capability slot for the prompt endpoint (minted at
/// spawn — the default grant; D reads it to build its requests).
static TASK_D_CAP: AtomicUsize = AtomicUsize::new(0);
/// The spawned sandbox's manifest profile (policy plane for prompts).
static mut PROFILE: u8 = PROFILE_STD;

/// Install the service configuration (kmain, before spawning S).
/// CEP: CEP-1 | Complete
/// Cost: O(1). Fail: panics on double-configure (wiring is once-only).
pub fn configure(cfg_in: Config) {
    unsafe {
        let cur: Option<Config> = core::ptr::read(core::ptr::addr_of!(CFG));
        if cur.is_some() {
            panic_str("identity: double configure", "");
        }
        CFG = Some(cfg_in);
    }
}

#[allow(static_mut_refs)]
fn cfg() -> Config {
    unsafe {
        let c: Option<Config> = core::ptr::read(core::ptr::addr_of!(CFG));
        match c {
            Some(c) => c,
            None => panic_str("identity: service used before configure", ""),
        }
    }
}

/// The sandbox's task slot (requesters fill their request's task field
/// from this; the service cross-checks it).
/// CEP: CEP-1 | Complete
/// Cost: one load. Fail: cannot fail.
pub fn sandbox_task() -> usize {
    TASK_D.load(Ordering::Relaxed)
}

/// Spawn a RING-3 user task from an ELF image under an operator-vouched
/// manifest (v0.8.0). The manifest's content hash binds the WHOLE ELF
/// image (BLAKE2b-256 over the bytes — the same refusal order as
/// spawn_from_manifest: MAC first, then hash, then profile). The loader
/// (elf.rs) maps W^X segments inside the code window and a private
/// stack; the default grant is the SAME as the kernel-function spawn:
/// exactly one capability — SEND/RECV on the prompt/fast endpoint —
/// recorded BEFORE the cap exists, delivered to the program in RDI.
///
/// Refusal inertness: verification refusals (MAC/hash/profile/ELF) touch
/// nothing; resource refusals leave wiped-or-parked frames only.
///
/// CEP: CEP-1 | Complete
/// Cost: one BLAKE2b (MAC) + one BLAKE2b (hash) + loader maps + 1 mint.
/// Fail: named SpawnError / ElfError (the caller prints refusals).
pub fn spawn_elf_from_manifest(
    img: &'static [u8],
    m: &Manifest,
    code_base: u64,
) -> Result<usize, SpawnError> {
    // 1. MAC under the vault key (fail-closed on a closed vault).
    let mut key = kms::manifest_key().map_err(|_| SpawnError::VaultClosed)?;
    let mut prefix = [0u8; PREFIX_LEN];
    m.encode_prefix(&mut prefix);
    let mut mac = [0u8; MAC_LEN];
    let mac_rc = ffi::blake2b(&mut mac, &prefix, &key);
    scrub(&mut key);
    mac_rc.map_err(SpawnError::Crypto)?;
    let mut diff = 0u8;
    for i in 0..MAC_LEN {
        diff |= mac[i] ^ m.mac[i];
    }
    if diff != 0 {
        return Err(SpawnError::MacMismatch);
    }

    // 2. Content binding over the WHOLE image (no entry-addr prefix:
    //    the loader resolves the entry from the validated ELF header).
    let mut hash = [0u8; 32];
    ffi::blake2b(&mut hash, img, &[]).map_err(SpawnError::Crypto)?;
    if hash != m.binary_hash {
        return Err(SpawnError::HashMismatch);
    }

    // 3. Profile validity.
    if m.profile != PROFILE_STD && m.profile != PROFILE_STRICT {
        return Err(SpawnError::Profile);
    }

    // 4. Load (W^X segments, validated window, private stack).
    let root = pagemap::new_task_root().map_err(|_| SpawnError::Paging)?;
    let slot_hint = 0; // stack address uses the task slot, resolved below
    let _ = slot_hint;
    // Resolve the task slot FIRST so the stack window can be slot-scoped.
    let idx = match task::free_slot() {
        Some(i) => i,
        None => return Err(SpawnError::Paging),
    };
    let stack_top = pagemap::USER_STACK_BASE + (idx as u64) * pagemap::USER_STACK_STRIDE;
    let (rip, rsp) = crate::elf::load(root, img, code_base, stack_top, 4)
        .map_err(|e| {
            e.print();
            SpawnError::BadEntry
        })?;

    // 5. Default grant: RECORD FIRST, then mint (no cap without record).
    append_record(Record {
        task: idx,
        auth: AUTH_PROMPT,
        scope: Scope::Session,
        decision: Decision::Granted,
        at_tick: task::ticks(),
        note: "default-grant-elf",
    });
    let ep = cfg().ep_prompt;
    let cap_slot = cap::table_of(idx)
        .mint(ep, RW)
        .map_err(SpawnError::DefaultGrant)?;

    // 6. Materialize the task (slot idx is now reserved for this image).
    let d = task::spawn_user_in(idx, rip, rsp, cap_slot as u64);
    task::tasks()[d].cr3 = root;
    task::tasks()[d].pcid = pagemap::pcid_of(root);

    serial::print(format_args!(
        "[S] ELF spawn: slot {}, root {:#x}, rip {:#x}, cap slot {} (rdi), pcid {}\n",
        d,
        root,
        rip,
        cap_slot,
        task::tasks()[d].pcid
    ));
    Ok(d)
}

/// The sandbox's prompt-endpoint capability slot (the default grant).
/// CEP: CEP-1 | Complete
/// Cost: one load. Fail: cannot fail.
pub fn sandbox_cap() -> usize {
    TASK_D_CAP.load(Ordering::Relaxed)
}

/// The prompt endpoint index (D's requests and S's replies share it).
/// CEP: CEP-1 | Complete
/// Cost: O(1). Fail: panics if used before configure (wiring contract).
pub fn prompt_ep() -> usize {
    cfg().ep_prompt
}

// --- Prompt protocol (32-byte fixed records over the prompt endpoint) --------

pub const REQ_LEN: usize = 32;
/// Request kinds ([8..16] field).
pub const KIND_LEASE: u64 = 1;
pub const KIND_DISK: u64 = 2;
pub const KIND_DONE: u64 = 3;
pub const KIND_EXPIRED: u64 = 4;
/// Reply decisions ([0..8] field).
pub const DEC_GRANTED: u64 = 1;
pub const DEC_DENIED: u64 = 2;

/// The identity service task body (spawned by kmain, runs forever —
/// actually: until the demo completes, then it exits via task_exit).
///
/// Flow: wait for the vault-open signal (C unlocked the vault) -> stage
/// manifests (valid / bad-MAC / bad-hash) -> run the three spawn attempts
/// (two refusals + one real spawn) -> serve prompt requests (policy cap,
/// operator grant/deny, lease-expiry reports) until the demo-done
/// request -> audit the tracker -> signal completion to C.
///
/// CEP: CEP-1 | Complete
/// Cost: O(spawn attempts) + O(prompts) + O(tracker audit).
/// Fail: panics on kernel-contract breaches; operator answers other than
///       y/Y deny (fail-closed default).
pub fn service(me: usize) -> ! {
    // 1. Wait for C's vault-open signal (delivery IS the sync point).
    let mut buf = [0u8; REQ_LEN];
    let n = recv_blocking(me, cfg().ep_done, cfg().cap_done, &mut buf);
    serial::print(format_args!(
        "[S] vault open (signal {} bytes) — identity service live\n",
        n
    ));

    // 2. Stage manifests. The valid one vouches for the real demo entry
    //    under the STRICT profile with both authorities requested.
    let mut m_valid = Manifest {
        profile: PROFILE_STRICT,
        req_lease: true,
        req_disk: true,
        lease_ttl: STRICT_LEASE_TTL_MAX,
        binary_hash: fn_identity_hash(cfg().demo_entry),
        entry: cfg().demo_entry,
        mac: [0; MAC_LEN],
    };
    m_valid.sign();
    // Forgery variant: one flipped MAC bit (same everything else).
    let mut m_macbad = m_valid;
    m_macbad.mac[0] ^= 0x01;
    // Substitution variant: correctly signed, but vouching for DIFFERENT
    // content than the entry that will run (decoy hash, real entry).
    let mut m_hashbad = m_valid;
    m_hashbad.binary_hash = fn_identity_hash(cfg().decoy_entry);
    m_hashbad.mac = [0; MAC_LEN];
    m_hashbad.sign();

    // 3. The three spawn attempts.
    match spawn_from_manifest(&m_macbad) {
        Err(SpawnError::MacMismatch) => {
            serial::print(format_args!(
                "[S] forged manifest refused at the MAC (bit-flip detected)\nREDOS IDNT MAC-REFUSED\n"
            ));
        }
        Err(other) => serial::print(format_args!(
            "[S] FAIL: expected MacMismatch, got {:?}\n",
            other
        )),
        Ok(_) => serial::print(format_args!("[S] FAIL: forged manifest ACCEPTED\n")),
    }
    match spawn_from_manifest(&m_hashbad) {
        Err(SpawnError::HashMismatch) => {
            serial::print(format_args!(
                "[S] substituted binary refused at the content hash\nREDOS IDNT HASH-REFUSED\n"
            ));
        }
        Err(other) => serial::print(format_args!(
            "[S] FAIL: expected HashMismatch, got {:?}\n",
            other
        )),
        Ok(_) => serial::print(format_args!("[S] FAIL: substituted binary ACCEPTED\n")),
    }
    match spawn_from_manifest(&m_valid) {
        Ok(d) => {
            TASK_D.store(d, Ordering::Relaxed);
            unsafe { PROFILE = m_valid.profile };
            serial::print(format_args!(
                "[S] sandbox spawned: slot {}, root {:#x}, code window {:#x} (RO), default grant: PROMPT RW\n",
                d,
                task::tasks()[d].cr3,
                DEMO_BASE
            ));
            serial::print(format_args!("REDOS IDNT SPAWN PASS\n"));
        }
        Err(other) => panic_str("identity: valid manifest refused: ", &format_dbg(&other)),
    }

    // 4. Prompt loop.
    loop {
        let mut req = [0u8; REQ_LEN];
        recv_blocking(me, cfg().ep_prompt, cfg().cap_prompt, &mut req);
        let claimed = u64::from_le_bytes(req[0..8].try_into().unwrap()) as usize;
        let kind = u64::from_le_bytes(req[8..16].try_into().unwrap());
        let arg = u64::from_le_bytes(req[16..24].try_into().unwrap());

        if kind == KIND_DONE {
            // Demo complete: acknowledge, then audit.
            reply(me, DEC_GRANTED, 0, 0);
            break;
        }

        // Every real request must come from the one sandbox slot.
        if claimed != sandbox_task() {
            append_record(Record {
                task: claimed,
                auth: kind_to_auth(kind),
                scope: Scope::Session,
                decision: Decision::Denied,
                at_tick: task::ticks(),
                note: "forged-request",
            });
            serial::print(format_args!(
                "[S] request claims task {} (sandbox is {}) — denied as forged\n",
                claimed,
                sandbox_task()
            ));
            reply(me, DEC_DENIED, 0, 0);
            continue;
        }

        match kind {
            KIND_LEASE => {
                handle_lease_request(me, arg);
            }
            KIND_DISK => {
                handle_disk_request(me);
            }
            KIND_EXPIRED => {
                let lease_id = arg as usize;
                note_lease_expired(claimed, lease_id);
                serial::print(format_args!(
                    "[S] tracker: task {} lease {} recorded Expired\n",
                    claimed, lease_id
                ));
                reply(me, DEC_GRANTED, 0, 0);
            }
            _ => {
                serial::print(format_args!("[S] unknown request kind {} — denied\n", kind));
                reply(me, DEC_DENIED, 0, 0);
            }
        }
    }

    // 5. Wait for D to actually EXIT (the done reply only unblocks D —
    // its task_exit, where session death happens mechanically, runs
    // after). Fair spins: yield_tick hands D the CPU it needs to die.
    let d = sandbox_task();
    loop {
        let dead = matches!(task::tasks()[d].state, task::TaskState::Dead);
        if dead {
            break;
        }
        task::yield_tick(me);
    }

    // 6. Tracker audit (the Permission-Tracker exit evidence).
    audit_and_complete(me)
}

/// Lease request path: mechanical TTL policy cap first, operator second.
/// CEP: CEP-1 | Complete
/// Fail: denials are recorded; grants are recorded BEFORE the lease
///       exists (no grant without record).
fn handle_lease_request(me: usize, ttl: u64) {
    let d = sandbox_task();
    if !lease_ttl_admitted(unsafe { PROFILE }, ttl) {
        append_record(Record {
            task: d,
            auth: AUTH_LEASE,
            scope: Scope::Session,
            decision: Decision::Denied,
            at_tick: task::ticks(),
            note: "ttl-over-policy-cap",
        });
        serial::print(format_args!(
            "[S] ttl {} exceeds the STRICT cap ({} ticks) — denied mechanically, no prompt\nREDOS IDNT POLICY-REFUSED\n",
            ttl, STRICT_LEASE_TTL_MAX
        ));
        reply(me, DEC_DENIED, 0, 0);
        return;
    }
    let mut q = [0u8; 96];
    // Manual prompt assembly (no_std: no format! for &str building).
    let bytes = b"[PROMPT-LEASE] task D requests KMS lease ttl=";
    q[..bytes.len()].copy_from_slice(bytes);
    let mut used = bytes.len();
    used += write_u64(&mut q[used..], ttl);
    let suffix = b" ticks - GRANT? [y/n] ";
    q[used..used + suffix.len()].copy_from_slice(suffix);
    used += suffix.len();
    let granted = ask_operator(&q[..used], me);
    if granted {
        // Record BEFORE the mint — the tracker invariant is universal
        // (no authority without a record). The lease id is only known
        // after the KMS grant succeeds; the Granted record carries the
        // decision, and the id joins the ledger at the expiry report
        // (Scope::Lease(id)). If the KMS grant fails, the Denied record
        // below supersedes (latest-decision-wins keeps failure
        // conservative: the authority was never live).
        append_record(Record {
            task: d,
            auth: AUTH_LEASE,
            scope: Scope::Session,
            decision: Decision::Granted,
            at_tick: task::ticks(),
            note: "operator-y (lease)",
        });
        match kms::lease_grant(ttl, d) {
            Ok(id) => {
                let exp = task::ticks() + ttl;
                serial::print(format_args!(
                    "[S] lease {} granted to task {} (expires tick {})\n",
                    id, d, exp
                ));
                reply(me, DEC_GRANTED, id as u64, exp);
            }
            Err(e) => {
                append_record(Record {
                    task: d,
                    auth: AUTH_LEASE,
                    scope: Scope::Session,
                    decision: Decision::Denied,
                    at_tick: task::ticks(),
                    note: "kms-error",
                });
                serial::print(format_args!(
                    "[S] FAIL: lease grant error {:?} — replying denied\n",
                    e
                ));
                reply(me, DEC_DENIED, 0, 0);
            }
        }
    } else {
        append_record(Record {
            task: d,
            auth: AUTH_LEASE,
            scope: Scope::Session,
            decision: Decision::Denied,
            at_tick: task::ticks(),
            note: "operator-n",
        });
        serial::print(format_args!("[S] lease request DENIED by operator\n"));
        reply(me, DEC_DENIED, 0, 0);
    }
}

/// Disk request path: straight to the operator (session-scoped grant).
/// CEP: CEP-1 | Complete
/// Fail: denials recorded; grants recorded before any use is possible.
fn handle_disk_request(me: usize) {
    let d = sandbox_task();
    let bytes = b"[PROMPT-DISK] task D requests DISK RW - GRANT? [y/n] ";
    let mut q = [0u8; 96];
    q[..bytes.len()].copy_from_slice(bytes);
    let granted = ask_operator(&q[..bytes.len()], me);
    if granted {
        append_record(Record {
            task: d,
            auth: AUTH_DISK,
            scope: Scope::Session,
            decision: Decision::Granted,
            at_tick: task::ticks(),
            note: "operator-y",
        });
        serial::print(format_args!("[S] DISK authority granted to task {}\n", d));
        reply(me, DEC_GRANTED, 0, 0);
    } else {
        append_record(Record {
            task: d,
            auth: AUTH_DISK,
            scope: Scope::Session,
            decision: Decision::Denied,
            at_tick: task::ticks(),
            note: "operator-n",
        });
        serial::print(format_args!("[S] DISK authority DENIED by operator\n"));
        reply(me, DEC_DENIED, 0, 0);
    }
}

/// The tracker audit + completion signal to C.
/// CEP: CEP-1 | Complete
/// Fail: panics on any invariant breach (the audit must be honest).
fn audit_and_complete(me: usize) -> ! {
    let d = sandbox_task();
    let (g, den, rv, ex) = count_for_task(d);
    let empty = cap::table_empty(d);
    let no_disk = !has_authority(d, AUTH_DISK);
    let no_lease = !has_authority(d, AUTH_LEASE);
    serial::print(format_args!(
        "[S] tracker audit: {} total records; task D: granted={} denied={} revoked={} expired={}; table empty: {}; live disk auth: {}; live lease auth: {}\n",
        record_count(), g, den, rv, ex, empty, !no_disk, !no_lease
    ));
    if empty && no_disk && no_lease && g == 2 && den == 2 && rv == 1 && ex == 1 {
        serial::print(format_args!(
            "[S] every authority expired or revoked at exit; ledger complete\nREDOS IDNT TRACKER PASS\n"
        ));
    } else {
        panic_str(
            "identity: tracker audit failed (see counts above)",
            "",
        );
    }

    // --- v0.8.0: ELF ring-3 spawn + register fast path + containment ----
    elf_fastpath_scenario(me);

    // Completion signal to C (unblocks the duress phase of the scenario).
    let done = [b'D'];
    send(me, cfg().ep_done, cfg().cap_done, &done);
    serial::print(format_args!("REDOS IDNT TEST COMPLETE\n"));
    serial::print(format_args!("[S] done\n"));
    task::task_exit(me)
}

/// The v0.8.0 ELF scenario: three manifests (fast-path server, client,
/// fault demo), three ring-3 spawns, the register rendezvous round trip
/// verified BY THE USER PROGRAMS (the kernel never sees the payload
/// values), and contained fault containment. Banners:
///   REDOS RING3 PASS    — both user programs pinged through the
///                         syscall/sysret round trip and exited 0
///   REDOS FASTPATH PASS — the rendezvous delivered registers verified
///                         by srv itself; exactly-once delivery held
///   REDOS USRFAULT PASS — faulty's ring-3 #PF was contained; srv/cli
///                         were unaffected (they exited before it ran)
/// CEP: CEP-1 | Complete
/// Cost: 3 spawns + a poll loop (cooperative yields) + one delivery.
/// Fail: FAIL lines / named panics (scenario discipline).
fn elf_fastpath_scenario(me: usize) {
    use pagemap::USER_CODE_BASE;
    // Link bases (usr/Makefile fragment + usr/link.ld --defsym): one
    // 2 MiB slot per program inside the user code window (PML4[252]).
    const SRV_BASE: u64 = USER_CODE_BASE + 0x20_0000;
    const CLI_BASE: u64 = USER_CODE_BASE + 0x40_0000;
    const FAULTY_BASE: u64 = USER_CODE_BASE + 0x60_0000;

    let mk_manifest = |img: &'static [u8]| -> Manifest {
        let mut h = [0u8; 32];
        ffi::blake2b(&mut h, img, &[]).unwrap_or_else(|e| panic_str("manifest hash: ", e));
        let mut m = Manifest {
            profile: PROFILE_STRICT,
            req_lease: false,
            req_disk: false,
            lease_ttl: 0,
            binary_hash: h,
            entry: 0, // ELF: the loader resolves from the validated header
            mac: [0; MAC_LEN],
        };
        m.sign();
        m
    };

    // 1. Spawn the server (it pings, then parks in a register recv).
    let srv = match spawn_elf_from_manifest(cfg().elf_srv, &mk_manifest(cfg().elf_srv), SRV_BASE) {
        Ok(s) => s,
        Err(e) => panic_str("identity: srv spawn refused: ", spawn_dbg(&e)),
    };
    // 2. Spawn the client (it pings, then sends the register payload).
    let cli = match spawn_elf_from_manifest(cfg().elf_cli, &mk_manifest(cfg().elf_cli), CLI_BASE) {
        Ok(s) => s,
        Err(e) => panic_str("identity: cli spawn refused: ", spawn_dbg(&e)),
    };
    serial::print(format_args!(
        "[S] ring-3 spawns: srv={} cli={} (default grant: one fast-endpoint cap in RDI)\n",
        srv, cli
    ));

    // 3. Poll to completion (cooperative: ticks advance for everyone).
    let mut spins = 0u32;
    loop {
        let ts = task::tasks();
        let srv_dead = matches!(ts[srv].state, task::TaskState::Dead);
        let cli_dead = matches!(ts[cli].state, task::TaskState::Dead);
        if srv_dead && cli_dead {
            break;
        }
        spins += 1;
        if spins > 100_000 {
            panic_str("identity: fast-path scenario stuck (no completion)", "");
        }
        task::yield_tick(me);
    }
    let srv_code = task::EXIT_CODE[srv].load(Ordering::Relaxed);
    let cli_code = task::EXIT_CODE[cli].load(Ordering::Relaxed);
    serial::print(format_args!(
        "[S] user exits: srv={} cli={} (0 = ping + payload verified by the program itself)\n",
        srv_code, cli_code
    ));
    if srv_code == 0 && cli_code == 0 {
        serial::print(format_args!(
            "[S] ring-3 round trips verified by the programs (kernel payload-blind throughout)\nREDOS RING3 PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[S] FAIL: user exit codes nonzero (srv={} cli={})\n",
            srv_code, cli_code
        ));
    }
    if crate::fastpath::deliver_count() == 1 {
        serial::print(format_args!(
            "[S] register rendezvous: exactly-once delivery held (deliver_count=1)\nREDOS FASTPATH PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[S] FAIL: delivery count {} != 1\n",
            crate::fastpath::deliver_count()
        ));
    }

    // 4. The containment demo: faulty dereferences an unmapped VA in
    //    ring 3 — the kernel contains the #PF and keeps running.
    let faulty = match spawn_elf_from_manifest(
        cfg().elf_faulty,
        &mk_manifest(cfg().elf_faulty),
        FAULTY_BASE,
    ) {
        Ok(s) => s,
        Err(e) => panic_str("identity: faulty spawn refused: ", spawn_dbg(&e)),
    };
    let mut spins2 = 0u32;
    loop {
        if matches!(task::tasks()[faulty].state, task::TaskState::Dead) {
            break;
        }
        spins2 += 1;
        if spins2 > 100_000 {
            panic_str("identity: faulty scenario stuck", "");
        }
        task::yield_tick(me);
    }
    let fcode = task::EXIT_CODE[faulty].load(Ordering::Relaxed);
    if fcode == task::EXIT_FAULT_MARKER {
        serial::print(format_args!(
            "[S] fault contained: faulty killed by the kernel, scenario unaffected\nREDOS USRFAULT PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[S] FAIL: faulty exit {:#x} != FAULT_MARKER\n",
            fcode
        ));
    }
}

/// SpawnError debug name (refusals print verbatim; no Debug derive on
/// the type keeps the enum's surface explicit).
fn spawn_dbg(e: &SpawnError) -> &'static str {
    match e {
        SpawnError::VaultClosed => "VaultClosed",
        SpawnError::MacMismatch => "MacMismatch",
        SpawnError::BadEntry => "BadEntry",
        SpawnError::HashMismatch => "HashMismatch",
        SpawnError::Profile => "Profile",
        SpawnError::Paging => "Paging",
        SpawnError::DefaultGrant(_) => "DefaultGrant",
        SpawnError::Crypto(_) => "Crypto",
    }
}

// --- IPC helpers (S's own table; same delivered-flag dance as main.rs) -------

fn recv_blocking(me: usize, ep: usize, cap_slot: usize, buf: &mut [u8]) -> usize {
    loop {
        {
            let ts = task::tasks();
            if ts[me].delivered {
                ts[me].delivered = false;
                return ts[me].recv_len;
            }
        }
        match ipc::ipc_recv(me, cap::table_of(me), cap_slot, ep, buf.as_mut_ptr(), buf.len()) {
            Ok(n) => return n,
            Err(IpcRecvError::Block) => task::schedule_from(me),
            Err(IpcRecvError::Contract(e)) => panic_str("identity recv: ", e),
        }
    }
}

fn reply(me: usize, decision: u64, lease_id: u64, expires: u64) {
    let mut out = [0u8; REQ_LEN];
    out[0..8].copy_from_slice(&decision.to_le_bytes());
    out[8..16].copy_from_slice(&lease_id.to_le_bytes());
    out[16..24].copy_from_slice(&expires.to_le_bytes());
    send(me, cfg().ep_prompt, cfg().cap_prompt, &out);
}

fn send(me: usize, ep: usize, cap_slot: usize, data: &[u8]) {
    match ipc::ipc_send(me, cap::table_of(me), cap_slot, ep, data) {
        Ok(()) => {}
        Err(IpcSendError::Block) => task::schedule_from(me),
        Err(IpcSendError::Contract(e)) => panic_str("identity send: ", e),
    }
}

// --- Small helpers ------------------------------------------------------------

/// Operator prompt: print, read one line (plain echo — decisions are
/// audit evidence), interpret. Anything except y/Y is a denial (the
/// fail-closed default: silence means no).
/// CEP: CEP-1 | Complete
/// Cost: O(line).
/// Fail: read errors (too long) deny; empty lines deny.
fn ask_operator(question: &[u8], me: usize) -> bool {
    // The prompt is a trusted kernel string — build it as UTF-8 lossy-free
    // by construction (it only ever contains ASCII we wrote).
    let q = core::str::from_utf8(question).unwrap_or("[PROMPT] ");
    let mut line = [0u8; 4];
    let n = match input::read_line(q, Echo::Plain, me, &mut line) {
        Ok(n) => n,
        Err(_) => 0,
    };
    n == 1 && (line[0] == b'y' || line[0] == b'Y')
}

fn write_u64(buf: &mut [u8], mut v: u64) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[i] = tmp[n - 1 - i];
    }
    n
}

fn kind_to_auth(kind: u64) -> u32 {
    match kind {
        KIND_LEASE => AUTH_LEASE,
        KIND_DISK => AUTH_DISK,
        _ => 0,
    }
}

/// Volatile zero-scrub for key copies leaving this module (same hygiene
/// as kms::wipe_bytes; local because the vault's is private).
fn scrub(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::hint::black_box(buf);
}

fn format_dbg(e: &SpawnError) -> &'static str {
    match e {
        SpawnError::VaultClosed => "VaultClosed",
        SpawnError::MacMismatch => "MacMismatch",
        SpawnError::BadEntry => "BadEntry",
        SpawnError::HashMismatch => "HashMismatch",
        SpawnError::Profile => "Profile",
        SpawnError::Paging => "Paging",
        SpawnError::DefaultGrant(_) => "DefaultGrant",
        SpawnError::Crypto(_) => "Crypto",
    }
}

#[cold]
fn panic_str(msg: &str, reason: &str) -> ! {
    crate::panic_str(msg, reason)
}

fn kms_err(e: kms::KmsError) -> &'static str {
    match e {
        kms::KmsError::Dead => "Dead",
        kms::KmsError::Refused => "Refused",
        kms::KmsError::Sealed => "Sealed",
        kms::KmsError::NoSuchLease => "NoSuchLease",
        kms::KmsError::Expired => "Expired",
        kms::KmsError::Crypto(s) => s,
    }
}
