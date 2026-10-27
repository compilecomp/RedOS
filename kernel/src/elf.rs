//! RedOS kernel — minimal ELF64 loader for static user programs (v0.8.0).
//!
//! Scope (deliberate): PT_LOAD segments only, no PT_DYNAMIC, no interp,
//! no relocations — the Phase-2 program model is static freestanding
//! images (gcc -nostdlib, fixed link base inside the user code window).
//! This is the loader the fast-path milestone actually needs: W^X
//! segments, a validated address window, and a per-task stack.
//!
//! Security posture (the spawner's ELF half):
//! * Every p_vaddr / e_entry MUST land inside [code_base, code_base +
//!   CODE_WINDOW] — a top-level PML4-slot check (USER_CODE_BASE is its
//!   own PML4 index), so a crafted image cannot name kernel or identity
//!   space. Refusal is named (BadVaddr), never a silent clamp.
//! * Segment sizes are bounded (MAX_SEGMENT) — a manifest-vouched image
//!   is still bounded by the loader (hash-verified ≠ resource-trusted).
//! * W^X per segment: p_flags X&&!W → RX (no W, no NX), W → RW|NX,
//!   neither → R|NX. A segment claiming both W and X is refused (W^X is
//!   a policy here, not a preference).
//! * Frames come from the ephemeral allocator (General class) and are
//!   filled through the HHDM; BSS tails are zeroed explicitly (fresh
//!   frames may carry pre-wipe garbage from early boot).
//!
//! CEP: CEP-1 | Complete (Phase-2 ELF surface: static ET_EXEC, ≤ 8
//!       segments, ≤ 64 MiB window, ≤ 64 KiB per segment)
//! Cost: O(segments × pages) maps + O(file bytes) copies.
//! Fail: named ElfError for every malformed field (the spawner surfaces
//!       refusals verbatim; nothing is half-loaded — failures leave the
//!       fresh root discardable and the frames wiped-or-parked).
//! Assumes: little-endian x86_64 ELF64; called with interrupts disabled.

use crate::mm::pagemap::{self, hhdm_mut};
use crate::mm::phys::{self, PageClass, PAGE_SIZE};
use crate::serial;

// Program headers are parsed OFFSET-BASED (rd16/rd32/rd64 below), not
// through a repr(C) struct: an ELF64 phdr is 56 bytes of packed fields
// with no alignment guarantee in a byte slice, and a #[repr(C)] mirror
// would be a silent-ABI bet. The offsets are the spec's.
const PHDR_SIZE: u64 = 56;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

/// Loader limits (named policy, enforced below).
const MAX_PHNUM: usize = 8;
const MAX_SEGMENT: u64 = 64 * 1024;
/// The code window slice one program may use (validated against
/// [code_base, code_base + CODE_WINDOW)).
pub const CODE_WINDOW: u64 = 4 * 1024 * 1024;

/// Named loader refusals (the scenario prints them verbatim).
#[derive(Debug)]
pub enum ElfError {
    /// Magic/class/endianness/machine mismatch.
    NotElf64,
    /// Not a static executable (ET_EXEC required).
    NotExec,
    /// Program header table outside the image.
    BadPhoff,
    /// Too many segments (named static bound).
    TooManySegments,
    /// A segment's file range falls outside the image.
    BadOffset,
    /// p_vaddr or e_entry outside the validated window.
    BadVaddr,
    /// A segment exceeds the size bound.
    TooBig,
    /// A segment claims W and X (W^X policy refusal).
    WxSegment,
    /// Frame or paging allocation failed.
    Resource(&'static str),
}

impl ElfError {
    fn describe(&self) -> &'static str {
        match self {
            ElfError::NotElf64 => "not an ELF64 image",
            ElfError::NotExec => "not ET_EXEC (static image required)",
            ElfError::BadPhoff => "program header table out of bounds",
            ElfError::TooManySegments => "too many segments",
            ElfError::BadOffset => "segment file range out of bounds",
            ElfError::BadVaddr => "segment/entry outside the code window",
            ElfError::TooBig => "segment exceeds the size bound",
            ElfError::WxSegment => "segment claims W+X (W^X policy)",
            ElfError::Resource(e) => e,
        }
    }
}

/// Read a little-endian u64 from `img` at `off`.
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: returns None for out-of-bounds reads (the caller refuses).
fn rd64(img: &[u8], off: usize) -> Option<u64> {
    if off + 8 > img.len() {
        return None;
    }
    let mut v = [0u8; 8];
    v.copy_from_slice(&img[off..off + 8]);
    Some(u64::from_le_bytes(v))
}

fn rd32(img: &[u8], off: usize) -> Option<u32> {
    if off + 4 > img.len() {
        return None;
    }
    let mut v = [0u8; 4];
    v.copy_from_slice(&img[off..off + 4]);
    Some(u32::from_le_bytes(v))
}

fn rd16(img: &[u8], off: usize) -> Option<u16> {
    if off + 2 > img.len() {
        return None;
    }
    let mut v = [0u8; 2];
    v.copy_from_slice(&img[off..off + 2]);
    Some(u16::from_le_bytes(v))
}

/// Validate the ELF64 header (magic, class 2, little-endian, ET_EXEC,
/// EM_X86_64) and return (phoff, phentsize, phnum, entry).
/// CEP: CEP-1 | Complete
/// Cost: O(1) reads.
/// Fail: named ElfError for every mismatch.
fn validate(img: &[u8]) -> Result<(u64, u64, u64, u64), ElfError> {
    if img.len() < 64 || &img[0..4] != b"\x7fELF" {
        return Err(ElfError::NotElf64);
    }
    if img[4] != 2 || img[5] != 1 {
        return Err(ElfError::NotElf64); // 64-bit, little-endian
    }
    let etype = rd16(img, 16).ok_or(ElfError::NotElf64)?;
    if etype != 2 {
        return Err(ElfError::NotExec);
    }
    let machine = rd16(img, 18).ok_or(ElfError::NotElf64)?;
    if machine != 62 {
        return Err(ElfError::NotElf64); // EM_X86_64
    }
    let entry = rd64(img, 24).ok_or(ElfError::NotElf64)?;
    let phoff = rd64(img, 32).ok_or(ElfError::NotElf64)?;
    let phentsize = rd16(img, 54).ok_or(ElfError::NotElf64)? as u64;
    let phnum = rd16(img, 56).ok_or(ElfError::NotElf64)? as u64;
    if phentsize as u64 != PHDR_SIZE {
        return Err(ElfError::BadPhoff);
    }
    if phnum as usize > MAX_PHNUM {
        return Err(ElfError::TooManySegments);
    }
    // checked: a hostile phoff must not wrap past the bound (review M5).
    match phoff.checked_add(phnum * PHDR_SIZE) {
        Some(end) if end <= img.len() as u64 => {}
        _ => return Err(ElfError::BadPhoff),
    }
    Ok((phoff, phentsize, phnum, entry))
}

/// Load a static ELF64 image into `root`. Returns (rip, rsp) for
/// spawn_user. The stack window is the caller's policy (identity.rs);
/// this function maps `stack_pages` pages below `stack_top`, RW|NX|U.
///
/// CEP: CEP-1 | Complete
/// Cost: O(segments × pages).
/// Fail: named ElfError; nothing partial survives into authority (the
///       caller discards the root; frames are wiped-or-parked).
pub fn load(
    root: u64,
    img: &[u8],
    code_base: u64,
    stack_top: u64,
    stack_pages: usize,
) -> Result<(u64, u64), ElfError> {
    let (phoff, _phentsize, phnum, entry) = validate(img)?;

    let in_window = |v: u64| -> Result<(), ElfError> {
        if v < code_base || v >= code_base + CODE_WINDOW {
            return Err(ElfError::BadVaddr);
        }
        Ok(())
    };
    in_window(entry)?;

    for i in 0..phnum as usize {
        let ph = phoff as usize + i * PHDR_SIZE as usize;
        let p_type = rd32(img, ph).ok_or(ElfError::BadPhoff)?;
        if p_type != PT_LOAD {
            continue;
        }
        let p_flags = rd32(img, ph + 4).ok_or(ElfError::BadPhoff)?;
        let p_offset = rd64(img, ph + 8).ok_or(ElfError::BadPhoff)?;
        let p_vaddr = rd64(img, ph + 16).ok_or(ElfError::BadPhoff)?;
        let p_filesz = rd64(img, ph + 32).ok_or(ElfError::BadPhoff)?;
        let p_memsz = rd64(img, ph + 40).ok_or(ElfError::BadPhoff)?;

        if p_memsz == 0 {
            continue;
        }
        if p_memsz > MAX_SEGMENT || p_filesz > p_memsz {
            return Err(ElfError::TooBig);
        }
        match p_offset.checked_add(p_filesz) {
            Some(end) if end <= img.len() as u64 => {}
            _ => return Err(ElfError::BadOffset),
        }
        // Last byte of the segment must stay in the window (the +memsz-1
        // form catches a segment whose END runs off, not just its start).
        in_window(p_vaddr)?;
        in_window(p_vaddr + p_memsz - 1)?;
        // Page congruence: the loader slices file bytes per 4 KiB page at
        // (vaddr mod 4096) == 0 positions — an offset/vaddr residue
        // mismatch would load bytes at wrong in-page offsets SILENTLY
        // (review M6). Refuse instead.
        if (p_vaddr & 0xFFF) != (p_offset & 0xFFF) {
            return Err(ElfError::BadOffset);
        }

        // W^X policy: X&&!W → RX; W&&!X → RW|NX; both → refuse.
        let x = p_flags & PF_X != 0;
        let w = p_flags & PF_W != 0;
        if x && w {
            return Err(ElfError::WxSegment);
        }
        let (write, nx) = (w, !x);

        for off in (0..p_memsz).step_by(PAGE_SIZE as usize) {
            let frame = phys::alloc(PageClass::General)
                .ok_or(ElfError::Resource("pagemap: ELF frame exhausted"))?;
            let dst = hhdm_mut(frame) as *mut u8;
            // Copy the file-backed part of this page; zero the rest
            // (BSS tails AND the padding of a partial file page — fresh
            // frames are not guaranteed zeroed before their first wipe).
            let page_vaddr = p_vaddr + off;
            // Safety: `dst` is a frame we just allocated through the
            // HHDM; `src` is bounds-checked above; both stay in-page.
            let file_here = if off < p_filesz {
                let n = core::cmp::min(p_filesz - off, PAGE_SIZE);
                let src = &img[(p_offset + off) as usize..(p_offset + off + n) as usize];
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                    core::ptr::write_bytes(dst.add(src.len()), 0, (PAGE_SIZE as usize) - src.len());
                }
                true
            } else {
                false
            };
            if !file_here {
                unsafe { core::ptr::write_bytes(dst, 0, PAGE_SIZE as usize) };
            }
            pagemap::map_page_ex(root, page_vaddr & !0xFFF, frame, write, true, nx)
                .map_err(ElfError::Resource)?;
        }
    }

    // User stack: stack_pages below stack_top, RW + NX + U. The pages
    // ABOVE stack_top and the pages BELOW the mapping stay unmapped —
    // guard bands by construction (overflow faults to containment).
    let stack_frames = phys::alloc_contig(PageClass::General, stack_pages)
        .ok_or(ElfError::Resource("pagemap: ELF stack exhausted"))?;
    for i in 0..stack_pages as u64 {
        let va = stack_top - (stack_pages as u64 - i) * PAGE_SIZE;
        pagemap::map_page_ex(root, va, stack_frames + i * PAGE_SIZE, true, true, true)
            .map_err(ElfError::Resource)?;
    }

    serial::print(format_args!(
        "[elf] loaded: entry {:#x}, {} segment group(s), stack {:#x} ({} pages)\n",
        entry, phnum, stack_top, stack_pages
    ));
    Ok((entry, stack_top))
}

impl ElfError {
    /// Print helper (named refusals reach the serial log verbatim).
    pub fn print(&self) {
        serial::print(format_args!("[elf] refusal: {}\n", self.describe()));
    }
}
