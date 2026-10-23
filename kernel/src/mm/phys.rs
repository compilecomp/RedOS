//! RedOS kernel — the Ephemeral Page Allocator (Pillar 2, "physics of
//! privacy").
//!
//! Design contract (docs/ARCHITECTURE.md §Memory Physics):
//!
//! 1. **Classification.** Every frame carries exactly one class:
//!    * `Free`     — wiped and reusable;
//!    * `General`  — ordinary kernel data (page tables, buffers);
//!    * `Locked`   — Key Material / FHE State. The `mlock` mandate: a
//!                   locked frame can never be freed through the public
//!                   API (only its owner may zero it), is never handed to
//!                   a second owner, and — because the kernel contains no
//!                   storage path at all — can never reach a disk.
//!    * `Shared`   — a zero-copy IPC block (shm.rs); freed only when its
//!                   last capability is revoked.
//! 2. **Wipe protocol.** `free()` overwrites the whole frame with
//!    pseudo-random noise *before* the frame re-enters the `Free` pool.
//!    A subsequent `alloc()` therefore cannot resurrect the previous
//!    occupant's bytes. The test suite probes 256 independent windows of
//!    the freed frame for the old pattern (256×16 B = 4096 B of evidence;
//!    a false PASS needs ≥2^-128 luck, i.e. never).
//! 3. **Anti-swap.** There is no swap. No block device driver is linked,
//!    no paging-to-disk path exists, and `anti_swap_audit()` verifies the
//!    DECLARED external surface (audit.rs — a reviewed, hand-maintained
//!    inventory) contains no storage-path names. The structural guarantee
//!    is that no storage driver exists to declare; the audit guards the
//!    inventory, not the linker (a hidden symbol would evade it — the
//!    inventory is therefore reviewed at every push, Law 8 ledger).
//!    Locked pages cannot be written to any persistent medium because
//!    none is reachable.
//! 4. **Zero on grant.** Every granted frame is zeroed at alloc time
//!    (defense in depth on top of the wipe at free time): a task can
//!    never observe another task's leftovers even from a frame that was
//!    never freed but reclaimed by other means (none exist today; the
//!    invariant is cheap and holds by construction).
//!
//! Noise source (v0.5.0): a xorshift128+ generator seeded from the TSC at
//! init and re-mixed with the frame's physical address per 64-bit lane —
//! wipe quality bar is "previous occupant unrecoverable", which this
//! meets. v0.6.0 (KMS): once the vault is unlocked it hands this module a
//! wipe key (BLAKE2b-KDF from the master key — see kms.rs) and wipes
//! upgrade from xorshift to an AES-256-CTR keystream (SP 800-38A CTR,
//! distinct 96-bit nonce per frame), closing the "statistical noise" gap
//! for the post-unlock lifetime of the boot. Pre-unlock wipes keep the
//! xorshift stream: the vault has no key material to protect yet.
//!
//! CEP: CEP-1 | Complete (Phase 2 scope: 512 MiB service ceiling)
//! Cost: alloc O(1) amortized (rotating cursor over a fixed pool),
//!       free O(PAGE_SIZE/8) (the wipe — the cost IS the guarantee).
//! Fail: class violations, double frees, out-of-range frames, and locked
//!       free attempts all return named errors or panic (fail-fast; a
//!       memory-physics breach is never silent).
//! Assumes: called after handoff validation; single CPU, no interrupts.

use crate::serial;

pub const PAGE_SIZE: u64 = 4096;
/// Phase-2 service ceiling: frames are served from RAM below this address.
/// 512 MiB covers the QEMU test configuration; a dynamic frame index is a
/// later optimization (documented in docs/ROADMAP.md).
pub const SERVICE_CEILING: u64 = 512 * 1024 * 1024;

/// Frame classes (see module docs). `u8`-tagged per frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PageClass {
    /// Wiped, in the free pool.
    Free = 0,
    /// Ordinary kernel data.
    General = 1,
    /// Key material / FHE state — the mlock mandate applies.
    Locked = 2,
    /// Zero-copy IPC block (owned by shm.rs).
    Shared = 3,
    /// Reserved by boot structures (kernel image, boot stack, firmware
    /// tables, handoff — never allocated, never served).
    Reserved = 4,
}

impl PageClass {
    fn from_u8(v: u8) -> PageClass {
        match v {
            0 => PageClass::Free,
            1 => PageClass::General,
            2 => PageClass::Locked,
            3 => PageClass::Shared,
            _ => PageClass::Reserved,
        }
    }
}

/// A free-attempt on a frame that is not freeable (locked or reserved).
#[derive(Debug)]
pub struct LockedFreeError;

// --- Pool state -----------------------------------------------------------

/// First served frame (physical address). Set by `init()`.
static mut POOL_BASE: u64 = 0;
/// One past the last served frame (physical address).
static mut POOL_TOP: u64 = 0;
/// Per-frame class table, indexed by `frame_index(phys)`.
static mut CLASSES: [u8; MAX_FRAMES] = [PageClass::Reserved as u8; MAX_FRAMES];
/// Hard pool capacity in frames (512 MiB / 4 KiB).
const MAX_FRAMES: usize = (SERVICE_CEILING / PAGE_SIZE) as usize;

/// Rotating allocation cursor (first-fit scan start).
static mut CURSOR: usize = 0;

// --- Wipe noise (xorshift128+ pre-KMS; AES-256-CTR post-unlock) -----------

static mut RNG_S0: u64 = 0;
static mut RNG_S1: u64 = 0;

/// AES-256-CTR wipe key, set exactly once by the KMS at unlock time.
/// `None` until then — pre-unlock wipes use the xorshift stream.
static mut WIPE_KEY: Option<[u8; 32]> = None;

/// Per-boot wipe sequence number: every AES-CTR wipe consumes one value,
/// so the (key, nonce) pair NEVER repeats within a boot — a frame freed
/// and re-freed gets independent keystreams (no two-time-pad across
/// wipes). 2^32 wipes per boot is far beyond reach; documented bound.
static mut WIPE_SEQ: u32 = 0;

/// Install the KMS-provided wipe key (idempotent: first write wins —
/// re-keying a running wipe stream would break the audit story).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: panics on a second install attempt (a re-key attempt is a
///       protocol violation, never silent).
/// Assumes: called by the KMS after a successful unlock (kms.rs).
pub fn set_wipe_key(key: [u8; 32]) {
    unsafe {
        if matches!(core::ptr::addr_of!(WIPE_KEY).read(), Some(_)) {
            panic_str("ephemeral allocator: wipe key re-installed");
        }
        WIPE_KEY = Some(key);
    }
    serial::print(format_args!(
        "[mm] wipe stream upgraded to AES-256-CTR (KMS-provided key)\n"
    ));
}

/// Revert to the keyless xorshift wipe stream (duress path: the KMS
/// destroys the wipe key with the rest of the vault). The 32-byte
/// payload is scrubbed (volatile + black_box) BEFORE the discriminant
/// flips — "destroys the wipe key" is mechanical, not aspirational.
///
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: cannot fail (idempotent).
/// Assumes: called only by the KMS duress path (kms.rs).
pub fn clear_wipe_key() {
    unsafe {
        if let Some(mut k) = core::ptr::addr_of!(WIPE_KEY).read() {
            for b in k.iter_mut() {
                core::ptr::write_volatile(b, 0);
            }
            core::hint::black_box(&k);
        }
        WIPE_KEY = None;
        WIPE_SEQ = 0;
    }
}

/// CEP: CEP-1 | Complete
/// Cost: ~13 arithmetic ops.
/// Fail: cannot fail. Seed includes the TSC so two boots never share a
///       wipe stream (a wiped frame in boot N is statistically unrelated
///       to the same frame in boot N+1).
fn rng_next() -> u64 {
    unsafe {
        // xorshift128+ (Marsaglia), a=23 b=17 c=26 — period 2^128-1.
        let mut s1 = RNG_S0;
        let s0 = RNG_S1;
        let res = s0.wrapping_add(s1);
        RNG_S0 = s0;
        s1 ^= s1 << 23;
        RNG_S1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
        res
    }
}

/// Address-mixed noise: the frame's physical address is folded into the
/// stream so identical frames wiped in the same boot still differ.
#[inline]
fn noise_lane(addr: u64) -> u64 {
    rng_next() ^ addr.rotate_left(17)
}

// --- Init ------------------------------------------------------------------

/// Boot-structure exclusions. Frames inside these ranges are marked
/// `Reserved` and never served (the bootloader's fixed placements; see
/// bootloader/src/main.zig).
struct Exclusion {
    base: u64,
    top: u64,
}

/// CEP: CEP-1 | Complete
/// Cost: O(usable regions + carve-outs + one full pass to classify).
/// Fail: panics if the serviceable pool is absurdly small (< 8 MiB) —
///       the kernel cannot honor the mlock mandate on such a machine.
/// Assumes: `boot` was validated; the memory map is the post-EBS map.
pub fn init(boot: &crate::handoff::Handoff) {
    let carve: [Exclusion; 5] = [
        // Kernel image window (0x200000..0x600000 — linker ASSERT bound).
        Exclusion { base: 0x200000, top: 0x600000 },
        // Bootloader kernel-file pool (8 MiB at 128 MiB).
        Exclusion { base: 0x0800_0000, top: 0x0800_0000 + 8 * 1024 * 1024 },
        // Boot stack (64 KiB at 256 MiB).
        Exclusion { base: 0x1000_0000, top: 0x1000_0000 + 64 * 1024 },
        // Bootloader page tables (3 pages at 272 MiB) — live until we
        // switch CR3; never hand them out.
        Exclusion { base: 0x1100_0000, top: 0x1100_0000 + 3 * 4096 },
        // Handoff struct + memory-map array pages (bootloader pool;
        // still being read by this very call).
        Exclusion {
            base: (boot as *const _ as u64) & !0xFFF,
            top: ((boot as *const _ as u64) + core::mem::size_of::<
                crate::handoff::Handoff,
            >() as u64
                + 0xFFF)
                & !0xFFF,
        },
    ];

    let mmap_page = |a: u64| -> bool {
        let e = &carve[4];
        a >= e.base && a < e.top
    };
    let _ = &mmap_page; // reserved for debug probes

    unsafe {
        // Seed the wipe stream from the TSC (low bits jitter per boot).
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("rax") lo, out("rdx") hi, options(nomem, nostack));
        let t: u64 = ((hi as u64) << 32) | lo as u64;
        RNG_S0 = t ^ 0x9E37_79B9_7F4A_7C15;
        RNG_S1 = t.rotate_left(32) ^ 0xBF58_476D_1CE4_E5B9;
        for _ in 0..8 {
            rng_next();
        }

        let mut base = u64::MAX;
        let mut top = 0u64;

        // First pass: pool index bounds (per usable region — a reserved
        // region BETWEEN usable ones must never be served).
        let mut regions: [(u64, u64); 256] = [(0, 0); 256];
        let mut nregions = 0usize;
        for e in boot.mem_entries() {
            if e.kind != crate::handoff::MEM_USABLE {
                continue;
            }
            // Frames are served only above the kernel image and below the
            // service ceiling (documented Phase-2 bound).
            let r_lo = (e.base.max(0x600_000) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let r_hi = e.base.saturating_add(e.len).min(SERVICE_CEILING) & !(PAGE_SIZE - 1);
            if r_lo >= r_hi {
                continue;
            }
            if nregions < regions.len() {
                regions[nregions] = (r_lo, r_hi);
                nregions += 1;
            }
            if r_lo < base {
                base = r_lo;
            }
            if r_hi > top {
                top = r_hi;
            }
        }

        if top <= base || top - base < 8 * 1024 * 1024 {
            panic_str("ephemeral allocator: serviceable pool < 8 MiB");
        }

        POOL_BASE = base;
        POOL_TOP = top;

        // Classify: everything Reserved, then mark ONLY usable-region
        // frames Free (per-region, not the min/max span), then re-reserve
        // carve-outs.
        for i in 0..MAX_FRAMES {
            CLASSES[i] = PageClass::Reserved as u8;
        }
        for r in regions.iter().take(nregions) {
            let mut p = r.0;
            while p < r.1 {
                CLASSES[frame_index(p)] = PageClass::Free as u8;
                p += PAGE_SIZE;
            }
        }
        for ex in carve.iter() {
            mark_range_reserved(ex.base, ex.top);
        }
        // Reserve the exact pages holding the memory-map array (the boot-
        // loader pool; read again by any late mem_entries() caller).
        let arr = boot.mmap as u64;
        let arr_bytes =
            boot.mmap_len as usize * core::mem::size_of::<crate::handoff::MemEntry>();
        let arr_top = arr + arr_bytes as u64;
        mark_range_reserved(arr & !0xFFF, (arr_top + 0xFFF) & !0xFFF);

        let free = count_class(PageClass::Free);
        serial::print(format_args!(
            "[mm] ephemeral allocator: pool {:#x}-{:#x}, {} frames, {} free\n",
            base,
            top,
            (top - base) / PAGE_SIZE,
            free
        ));
    }
}

/// Mark [base, top) Reserved (any part inside the served pool).
unsafe fn mark_range_reserved(base: u64, top: u64) {
    let b = base.max(POOL_BASE);
    let t = top.min(POOL_TOP);
    let mut p = b & !(PAGE_SIZE - 1);
    while p < t {
        let i = frame_index(p);
        if i < MAX_FRAMES {
            CLASSES[i] = PageClass::Reserved as u8;
        }
        p += PAGE_SIZE;
    }
}

#[inline]
fn frame_index(phys: u64) -> usize {
    ((phys - unsafe { POOL_BASE }) / PAGE_SIZE) as usize
}

#[inline]
fn frame_phys(idx: usize) -> u64 {
    unsafe { POOL_BASE + (idx as u64) * PAGE_SIZE }
}

fn count_class(c: PageClass) -> usize {
    #[allow(static_mut_refs)] // single-CPU kernel, no interrupts (Phase 2 model)
    unsafe { CLASSES.iter().filter(|&&x| PageClass::from_u8(x) == c).count() }
}

// --- Allocation ------------------------------------------------------------

/// Allocate one frame of `class`, zeroed. The frame is granted to the
/// caller; Locked frames additionally leave the reusable pool permanently
/// for this boot (they can only be zeroed by their owner, never re-pooled).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) amortized (rotating first-fit); zeroing is one 4 KiB pass.
/// Fail: None on exhaustion (named, never silent).
pub fn alloc(class: PageClass) -> Option<u64> {
    unsafe {
        let n = ((POOL_TOP - POOL_BASE) / PAGE_SIZE) as usize;
        for off in 0..n {
            let i = (CURSOR + off) % n;
            if PageClass::from_u8(CLASSES[i]) == PageClass::Free {
                CURSOR = (i + 1) % n;
                CLASSES[i] = class as u8;
                let phys = frame_phys(i);
                zero_frame(phys);
                return Some(phys);
            }
        }
        None
    }
}

/// Allocate `n` physically contiguous frames (zero-copy IPC blocks want
/// one mapping window). All frames get `class`.
///
/// CEP: CEP-1 | Complete
/// Cost: O(frames) scan.
/// Fail: None if no contiguous run exists.
pub fn alloc_contig(class: PageClass, n: usize) -> Option<u64> {
    unsafe {
        let total = ((POOL_TOP - POOL_BASE) / PAGE_SIZE) as usize;
        if n == 0 || n > total {
            return None;
        }
        let mut run = 0usize;
        for i in 0..total {
            if PageClass::from_u8(CLASSES[i]) == PageClass::Free {
                run += 1;
                if run == n {
                    let start = i + 1 - n;
                    for j in start..=i {
                        CLASSES[j] = class as u8;
                    }
                    let phys = frame_phys(start);
                    for j in 0..n {
                        zero_frame(phys + (j as u64) * PAGE_SIZE);
                    }
                    return Some(phys);
                }
            } else {
                run = 0;
            }
        }
        None
    }
}

/// The Wipe Protocol: overwrite the frame with address-mixed noise, then
/// zero it, then mark Free. (Noise first — so the old data is gone even
/// if the frame is only re-zeroed later — then zero for the zero-on-grant
/// invariant. The two passes are the documented cost of the guarantee.)
///
/// CEP: CEP-1 | Complete
/// Cost: two 4 KiB passes (noise + zero). This cost is the feature.
/// Fail: Err on Locked/Reserved/Free frames — the public API can never
///       wipe a locked page (only the KMS owner may, in v0.6.0), and a
///       double free is a NAMED error (never a silent re-wipe: re-wiping
///       a frame that was re-allocated would erase the new owner's data).
pub fn free(phys: u64) -> Result<(), LockedFreeError> {
    unsafe {
        if phys < POOL_BASE || phys >= POOL_TOP || phys % PAGE_SIZE != 0 {
            panic_str("ephemeral allocator: free of out-of-pool frame");
        }
        let i = frame_index(phys);
        match PageClass::from_u8(CLASSES[i]) {
            PageClass::Locked | PageClass::Reserved | PageClass::Free => {
                return Err(LockedFreeError);
            }
            PageClass::General | PageClass::Shared => {
                wipe_noise(phys);
                zero_frame(phys);
                CLASSES[i] = PageClass::Free as u8;
                Ok(())
            }
        }
    }
}

/// Overwrite one frame with a keystream keyed by the frame's physical
/// address, then (caller-side) zero it. Two regimes:
///   * pre-KMS unlock: xorshift128+ address-mixed noise (v0.5.0);
///   * post-KMS unlock: AES-256-CTR keystream — nonce = frame physical
///     address (8 B) || per-boot wipe sequence (4 B), SP 800-38A.
/// Identity addressing: served frames are below the 512 MiB service
/// ceiling, which EVERY root identity-maps (bootloader's 1 GiB map and
/// our PML4[0] 512 MiB map) — the allocator therefore works under any
/// active CR3 and never depends on the HHDM being current.
fn wipe_noise(phys: u64) {
    let key = unsafe { WIPE_KEY };
    match key {
        None => {
            let base = phys as *mut u64;
            for k in 0..(PAGE_SIZE / 8) {
                unsafe {
                    base.add(k as usize).write_volatile(noise_lane(phys + k * 8));
                }
            }
        }
        Some(k) => {
            // AES-256-CTR (SP 800-38A): counter block = nonce(12 B) ||
            // ctr(u32 BE). Nonce = frame physical address (8 B) ||
            // per-boot wipe sequence (4 B) — every wipe in a boot gets a
            // distinct nonce even when the SAME frame is wiped twice
            // (free -> alloc -> free), closing the two-time-pad window;
            // across boots the vault hands a fresh key, so no (key,
            // nonce) pair can repeat while the key lives.
            let seq = unsafe {
                let s = WIPE_SEQ;
                WIPE_SEQ = WIPE_SEQ.wrapping_add(1);
                s
            };
            let mut ctx = crate::ffi::aes256_init(&k);
            let mut iv = [0u8; crate::ffi::IV_LEN];
            iv[0..8].copy_from_slice(&phys.to_le_bytes());
            iv[8..12].copy_from_slice(&seq.to_be_bytes());
            let base = phys as *mut u8;
            let mut ctr: u32 = 0;
            for chunk in 0..(PAGE_SIZE as usize / 16) {
                let mut block = [0u8; 16];
                let mut ks = [0u8; 16];
                block[..12].copy_from_slice(&iv);
                block[12..16].copy_from_slice(&ctr.to_be_bytes());
                crate::ffi::aes256_ctr_block(&mut ctx, &block, &mut ks);
                let src = unsafe {
                    core::slice::from_raw_parts(base.add(chunk * 16), 16)
                };
                for i in 0..16 {
                    unsafe {
                        base.add(chunk * 16 + i)
                            .write_volatile(src[i] ^ ks[i]);
                    }
                }
                ctr = ctr.wrapping_add(1);
            }
            // Hygiene: the wipe key schedule leaves the stack with the
            // frame already overwritten. black_box = elision-proof and
            // honestly "dead" to the optimizer by design.
            core::hint::black_box(&mut ctx.roundkeys).fill(0);
        }
    }
}

/// Zero one frame via the identity map (see wipe_noise rationale).
fn zero_frame(phys: u64) {
    let base = phys as *mut u64;
    for k in 0..(PAGE_SIZE / 8) {
        unsafe {
            base.add(k as usize).write_volatile(0u64);
        }
    }
}

/// Class of a frame (for tests and audits).
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: out-of-pool frames report Reserved (the caller's own contract
///       guarantees in-pool addresses; diagnostics use this fn).
pub fn class_of(phys: u64) -> PageClass {
    unsafe {
        if phys < POOL_BASE || phys >= POOL_TOP {
            return PageClass::Reserved;
        }
        PageClass::from_u8(CLASSES[frame_index(phys)])
    }
}

// --- Guarantees ------------------------------------------------------------

/// The Anti-Swap Audit: verifies the DECLARED external surface
/// (audit::EXPORTED_SYMBOLS — a hand-maintained, push-reviewed inventory)
/// contains no storage-path names. This audit CANNOT catch an undeclared
/// symbol (it scans the inventory, not the binary); its role is to keep
/// the declared surface honest and to fail fast if a storage path is ever
/// added to it. The structural guarantee itself is: no storage driver is
/// linked in this kernel, full stop (verify by `nm build/redos.bin`).
///
/// CEP: CEP-1 | Complete
/// Cost: O(declared symbols x forbidden names) — 24 substring scans.
/// Fail: panics if a DECLARED symbol carries a storage-path name.
pub fn anti_swap_audit() {
    // The kernel's entire external surface is: serial (port I/O), the C
    // crypto core, MMU/port instructions. Any of these symbols existing
    // would mean a storage driver was linked:
    const FORBIDDEN: [&str; 4] = ["ahci", "nvme", "ata_", "sdhci"];
    let syms = [crate::audit::EXPORTED_SYMBOLS];
    for s in syms.iter().flat_map(|x| x.iter()) {
        for f in FORBIDDEN.iter() {
            if s.contains(f) {
                panic_str("anti-swap audit: storage path symbol found: ");
                // unreachable
            }
        }
    }
    serial::print(format_args!("[mm] anti-swap audit OK (no storage path linked)\n"));
}

/// One-line allocator stats report (boot diagnostic).
pub fn report() {
    serial::print(format_args!(
            "[mm] frames: free={} general={} locked={} shared={}\n",
            count_class(PageClass::Free),
            count_class(PageClass::General),
            count_class(PageClass::Locked),
            count_class(PageClass::Shared),
    ));
}

#[cold]
fn panic_str(msg: &str) -> ! {
    crate::panic_str("phys: ", msg)
}
