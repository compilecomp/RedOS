//! RedOS kernel — the XTS-encrypted RAM disk (Pillar 2, v0.6.0).
//!
//! The disk is a contiguous run of `General`-class frames; every 512-byte
//! sector is one XTS-AES-256 data unit whose key is derived FRESH from
//! the vault master key for every operation and zeroized immediately
//! after (see kms::disk_key). Consequences:
//!
//! * **Encryption at rest.** A memory image of the disk region shows only
//!   ciphertext (the boot scenario asserts this: raw bytes != plaintext).
//! * **Per-sector tweak.** Sector `n` uses tweak `n` (IEEE 1619 data-unit
//!   numbering) — identical plaintext in different sectors encrypts
//!   differently, and sectors cannot be silently swapped without the
//!   block table noticing the decoy pattern (see `audit_sector`).
//! * **Vault-coupled lifetime.** Every read/write derives from the vault:
//!   once the duress wipe destroys the master key, all I/O fails closed
//!   (`KmsError::Dead`) — the disk is unreadable even though its frames
//!   still exist.
//!
//! Scope note (documented): this is a RAM block device for the Phase-2
//! milestone, not a filesystem. There is no partition table, no
//! scheduler, no write cache — each op is synchronous and O(sector).
//! Integrity: XTS is confidentiality-only; the demo's integrity story is
//! the block-table audit (`audit_sectors` — every allocated sector must
//! hold non-plaintext data under the current master key), which detects
//! wholesale plaintext injection. Full authenticated sectors (GCM per
//! sector) are a deliberate v0.7.0+ decision tracked in docs/ROADMAP.md.
//!
//! * **Authority-gated I/O (v0.7.0).** Every I/O call carries the caller's
//!   task index and consults the Permission Tracker (identity.rs):
//!   no live DISK authority, no I/O — `DiskError::NotGranted`, recorded
//!   policy, not a convention. The vault-coupled lifetime checks run
//!   FIRST (a dead vault fails closed before any authority question).
//!
//! CEP: CEP-1 | Complete (Phase 2 scope: 16 sectors of 512 B)
//! Cost: one XTS data-unit op per sector I/O (+ one BLAKE2b key
//!       derivation, which dominates at 512 B scale — and that IS the
//!       design: the key exists for the shortest possible time).
//! Fail: named errors; the disk refuses ALL I/O once the vault is dead,
//!       and refuses ALL I/O from tasks without live DISK authority.
//! Assumes: single CPU; called after kms is Unlocked (or expects the
//!          named Dead/Sealed errors otherwise); caller passes its true
//!          task index (ring-3 boundary makes this structural in v0.8.0).

use crate::mm::phys::{self, PageClass, PAGE_SIZE};
use crate::serial;

/// Sector size in bytes (one XTS data unit).
pub const SECTOR_SIZE: usize = 512;
/// Sector count (Phase-2 demo scale: 16 sectors = 8 KiB = 2 frames).
pub const SECTOR_COUNT: usize = 16;

/// The single RAM disk instance (Phase 2 has exactly one; multi-disk
/// arrives with the storage service, if ever — RAM-only design).
struct Disk {
    present: bool,
    /// Physical base of the contiguous frame run.
    base: u64,
    /// Frames consumed (SECTOR_SIZE*SECTOR_COUNT / PAGE_SIZE rounded up).
    frames: usize,
}

static mut DISK: Disk = Disk {
    present: false,
    base: 0,
    frames: 0,
};

/// Create the RAM disk (allocates General frames; contents zero).
///
/// CEP: CEP-1 | Complete
/// Cost: O(frames) alloc + zero-on-grant.
/// Fail: panic on frame exhaustion or double-create (a silent second
///       disk leaking the first is a resource-safety breach).
/// Assumes: called after phys::init; the vault may be sealed (creation
///          is legal — I/O is what requires keys).
pub fn create() {
    unsafe {
        if DISK.present {
            panic_str("ramdisk: double create");
        }
        let bytes = SECTOR_SIZE * SECTOR_COUNT;
        let frames = (bytes + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
        let base = phys::alloc_contig(PageClass::General, frames)
            .unwrap_or_else(|| panic_str("ramdisk: frames exhausted"));
        DISK.present = true;
        DISK.base = base;
        DISK.frames = frames;
        serial::print(format_args!(
            "[disk] XTS RAM disk online: {} sectors x {} B at phys {:#x} ({} frames, General)\n",
            SECTOR_COUNT, SECTOR_SIZE, base, frames
        ));
    }
}

/// I/O errors (named; CI prints them verbatim).
#[derive(Debug)]
pub enum DiskError {
    /// Vault destroyed (duress) — permanent, fail-closed.
    VaultDead,
    /// Vault not unlocked.
    VaultSealed,
    /// Vault refused at seal (strict-RNG policy) — terminal.
    VaultRefused,
    /// Caller holds no live DISK authority in the Permission Tracker.
    NotGranted,
    /// Sector index out of range.
    BadSector,
    /// C-core contract error.
    Crypto(#[allow(dead_code)] &'static str),
}

/// Authority gate (v0.7.0): the tracker decides, the disk enforces.
/// CEP: CEP-1 | Complete
/// Cost: O(tracker records) scan.
/// Fail: DiskError::NotGranted — named, never silent.
fn check_authority(owner: usize) -> Result<(), DiskError> {
    if crate::identity::has_authority(owner, crate::identity::AUTH_DISK) {
        Ok(())
    } else {
        Err(DiskError::NotGranted)
    }
}

/// Read one sector: XTS-decrypt(derive(master, sector n), stored ct).
///
/// CEP: CEP-1 | Complete
/// Cost: one tracker scan + one BLAKE2b derivation + one 512 B XTS
///       decrypt; the disk key lives only inside this call (stack),
///       zeroized on return.
/// Fail: DiskError::VaultDead/Refused/Sealed (fail-closed), NotGranted,
///       BadSector, Crypto.
pub fn read_sector(owner: usize, n: usize, out: &mut [u8; SECTOR_SIZE]) -> Result<(), DiskError> {
    let mut key = match crate::kms::disk_key() {
        Ok(k) => k,
        Err(crate::kms::KmsError::Dead) => return Err(DiskError::VaultDead),
        Err(crate::kms::KmsError::Refused) => return Err(DiskError::VaultRefused),
        Err(crate::kms::KmsError::Sealed) => return Err(DiskError::VaultSealed),
        Err(crate::kms::KmsError::Crypto(e)) => return Err(DiskError::Crypto(e)),
        Err(_) => return Err(DiskError::Crypto("UNKNOWN")),
    };
    let r = check_authority(owner).and_then(|()| read_sector_with_key(n, out, &key));
    zero_key(&mut key);
    r
}

/// Write one sector: XTS-encrypt(derive(master, sector n), pt) into the
/// frame slot. The data unit number IS the sector number.
///
/// CEP: CEP-1 | Complete
/// Cost: one tracker scan + one BLAKE2b derivation + one 512 B XTS
///       encrypt; key zeroized.
/// Fail: as read_sector.
pub fn write_sector(
    owner: usize,
    n: usize,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), DiskError> {
    let mut key = match crate::kms::disk_key() {
        Ok(k) => k,
        Err(crate::kms::KmsError::Dead) => return Err(DiskError::VaultDead),
        Err(crate::kms::KmsError::Refused) => return Err(DiskError::VaultRefused),
        Err(crate::kms::KmsError::Sealed) => return Err(DiskError::VaultSealed),
        Err(crate::kms::KmsError::Crypto(e)) => return Err(DiskError::Crypto(e)),
        Err(_) => return Err(DiskError::Crypto("UNKNOWN")),
    };
    let r = check_authority(owner).and_then(|()| write_sector_with_key(n, data, &key));
    zero_key(&mut key);
    r
}

/// Raw view of the stored (ciphertext) bytes of one sector — the
/// evidence channel for the encryption-at-rest assertion. No key needed:
/// this is what an attacker with a memory image sees.
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) copy.
/// Fail: panics (named) on a missing disk or an out-of-range sector —
///       this is a diagnostic channel with a caller-side contract
///       (the I/O path returns named errors instead; see read_sector).
pub fn raw_sector(n: usize, out: &mut [u8; SECTOR_SIZE]) {
    unsafe {
        if !DISK.present {
            panic_str("ramdisk: raw_sector before create");
        }
        if n >= SECTOR_COUNT {
            panic_str("ramdisk: raw_sector OOB");
        }
        let src = (DISK.base + (n as u64) * SECTOR_SIZE as u64) as *const u8;
        for (i, b) in out.iter_mut().enumerate() {
            *b = src.add(i).read_volatile();
        }
    }
}

/// Whether the disk exists (reserved for the v0.7.0 storage audit; kept
/// pub so the dead-code check is explicit about the intent).
#[allow(dead_code)]
pub fn present() -> bool {
    unsafe { DISK.present }
}

/// Physical base (audit/diagnostics; the contents are the secret, and
/// they are ciphertext — see module docs).
#[allow(dead_code)]
pub fn base_phys() -> u64 {
    unsafe { DISK.base }
}

// --- Key-carrying internals (private; key zeroized by the pub wrappers) -----

fn read_sector_with_key(
    n: usize,
    out: &mut [u8; SECTOR_SIZE],
    key: &[u8; crate::ffi::XTS_KEY_LEN],
) -> Result<(), DiskError> {
    unsafe {
        if !DISK.present {
            panic_str("ramdisk: I/O before create");
        }
        if n >= SECTOR_COUNT {
            return Err(DiskError::BadSector);
        }
        let slot = (DISK.base + (n as u64) * SECTOR_SIZE as u64) as *const u8;
        let mut stored = [0u8; SECTOR_SIZE];
        for (i, b) in stored.iter_mut().enumerate() {
            *b = slot.add(i).read_volatile();
        }
        crate::ffi::xts_decrypt(key, n as u64, &stored, out)
            .map_err(DiskError::Crypto)
    }
}

fn write_sector_with_key(
    n: usize,
    data: &[u8; SECTOR_SIZE],
    key: &[u8; crate::ffi::XTS_KEY_LEN],
) -> Result<(), DiskError> {
    unsafe {
        if !DISK.present {
            panic_str("ramdisk: I/O before create");
        }
        if n >= SECTOR_COUNT {
            return Err(DiskError::BadSector);
        }
        let slot = (DISK.base + (n as u64) * SECTOR_SIZE as u64) as *mut u8;
        let mut tmp = [0u8; SECTOR_SIZE];
        crate::ffi::xts_encrypt(key, n as u64, data, &mut tmp)
            .map_err(DiskError::Crypto)?;
        for (i, b) in tmp.iter().enumerate() {
            slot.add(i).write_volatile(*b);
        }
        Ok(())
    }
}

fn zero_key(key: &mut [u8; crate::ffi::XTS_KEY_LEN]) {
    for b in key.iter_mut() {
        *b = 0;
    }
}

#[cold]
fn panic_str(msg: &str) -> ! {
    crate::panic_str(msg, "")
}
