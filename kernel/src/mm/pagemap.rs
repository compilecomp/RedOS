//! RedOS kernel — 4-level x86_64 paging (Phase 2).
//!
//! Layout (canonical addresses, shared subtrees shared for real):
//!
//! * PML4[0]   — low identity map, 512 MiB via 2 MiB pages. Shared by
//!               every root (the kernel image, task stacks and boot
//!               structures live here).
//! * PML4[256] — higher-half direct map (HHDM) `0xFFFF_8000_0000_0000`,
//!               one 1 GiB page when the CPU supports it, else 2 MiB
//!               pages across the service ceiling. Shared by every root.
//!               This is how the kernel touches arbitrary physical frames.
//! * PML4[192] — the zero-copy shared-memory window (`SHM_BASE`), one
//!               1 GiB slot per block. Per-task subtrees: the SAME
//!               physical block is mapped read-only or read-write
//!               depending on which task's root is loaded.
//! * PML4[224] — per-task private window (`PRIV_BASE`). A page mapped
//!               here exists only in its owner's root; any other task
//!               probing that address takes a page fault. This is the
//!               hardware basis of app isolation in Phase 2.
//! * PML4[225] — a second private slot (`PRIV_ALT`) used by the isolation
//!               test as a page that exists in exactly one task's root.
//!
//! Revocation model: unmapping from a task's root + a full TLB flush on
//! the next CR3 load (no PCID in Phase 2 — see mm/mod.rs scope notes)
//! means the *next* access from that task takes a #PF. The idt.rs probe
//! protocol turns that hardware trap into a named "Access Denied" event.
//!
//! CEP: CEP-1 | Complete (Phase 2 scope)
//! Cost: map O(1) (bounded 4-level walk, allocating missing tables);
//!       unmap O(1); CR3 switch is a single mov (full flush).
//! Fail: map on a populated PTE, unmap of a non-present page, and table
//!       exhaustion all return named errors (fail-fast; the mmu layer
//!       never silently rewrites authority).
//! Assumes: long mode; bootloader's CR3 active during init(); the handoff
//!          and its memory map are NOT touched after `switch_to_kernel()`
//!          (they live in bootloader-owned pages that stay identity-mapped
//!          only by luck of placement — the kernel reads them once).

use crate::mm::phys::{self, PageClass, PAGE_SIZE};
use crate::serial;

/// Higher-half direct map offset (PML4[256]).
pub const HHDM_OFF: u64 = 0xFFFF_8000_0000_0000;
/// Zero-copy shared-memory window base (PML4[192]); block i lives at
/// `SHM_BASE + i * SHM_STRIDE`.
pub const SHM_BASE: u64 = 0x0000_6000_0000_0000;
pub const SHM_STRIDE: u64 = 1 << 30;
/// Per-task private window (PML4[224]).
pub const PRIV_BASE: u64 = 0x0000_7000_0000_0000;
/// A second private slot (PML4[225]) — used by the isolation test as a
/// page that exists in exactly one task's root.
pub const PRIV_ALT: u64 = 0x0000_7080_0000_0000;

const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_PS: u64 = 1 << 7;

/// PML4 indices for the fixed windows. Derived once here; the asserts
/// guarantee the three windows live in distinct top-level slots (so a
/// task root can carry per-window permissions independently).
const SHM_PML4: usize = (SHM_BASE >> 39) as usize & 0x1FF; // 192
const PRIV_PML4: usize = (PRIV_BASE >> 39) as usize & 0x1FF; // 224
const HHDM_PML4: usize = (HHDM_OFF >> 39) as usize & 0x1FF; // 256
const _: () = assert!(SHM_PML4 != PRIV_PML4);
const _: () = assert!(PRIV_PML4 != HHDM_PML4);
const _: () = assert!(SHM_PML4 != HHDM_PML4);
const _: () = assert!(PRIV_BASE < 0x0000_8000_0000_0000); // canonical, low half

static mut KERNEL_ROOT: u64 = 0;
static mut CURRENT_CR3: u64 = 0;

#[inline]
fn idx4(v: u64) -> usize {
    ((v >> 39) & 0x1FF) as usize
}
#[inline]
fn idx3(v: u64) -> usize {
    ((v >> 30) & 0x1FF) as usize
}
#[inline]
fn idx2(v: u64) -> usize {
    ((v >> 21) & 0x1FF) as usize
}
#[inline]
fn idx1(v: u64) -> usize {
    ((v >> 12) & 0x1FF) as usize
}

/// Physical → HHDM pointer (read).
/// CEP: CEP-1 | Complete
/// Cost: O(1) arithmetic.
/// Fail: cannot fail (caller guarantees the frame is HHDM-covered —
///       served frames are below the ceiling; the 1 GiB/2 MiB HHDM page
///       covers all of it).
pub fn hhdm(phys: u64) -> *const u8 {
    (HHDM_OFF + phys) as *const u8
}
/// Physical → HHDM pointer (write). See `hhdm` contract.
/// CEP: CEP-1 | Complete
/// Cost: O(1) arithmetic.
/// Fail: cannot fail (same coverage contract as `hhdm`).
pub fn hhdm_mut(phys: u64) -> *mut u8 {
    (HHDM_OFF + phys) as *mut u8
}

/// A page-table frame as a &mut [u64; 512] through the identity map.
/// Safety: `phys` must be a frame we own (General class).
/// Identity addressing (not the HHDM): served frames are below the 512
/// MiB service ceiling, identity-mapped by BOTH the bootloader's tables
/// (still active during init) and our own PML4[0] — so table construction
/// works before AND after the CR3 switch. Using the HHDM here would fault
/// (observed in v0.5.0 bring-up: the HHDM does not exist until we switch).
unsafe fn table(phys: u64) -> &'static mut [u64; 512] {
    &mut *(phys as *mut [u64; 512])
}

/// Guard: refuse to descend through a leaf (PS bit set) as if it were a
/// table pointer. The low identity (2 MiB pages) and the 1 GiB HHDM page
/// are leaves; treating their entries as table pointers would silently
/// corrupt physical memory (review M2, v0.5.0). 4 KiB-map windows (SHM,
/// PRIV) never set PS.
/// Safety: caller holds the containing table via the HHDM/identity map.
unsafe fn leaf_check(entry: u64, what: &str) -> Result<(), &'static str> {
    if entry & PTE_PS != 0 {
        return Err("pagemap: leaf entry where a table was expected");
    }
    let _ = what;
    Ok(())
}

fn cpu_has_1g_pages() -> bool {
    // cpuid clobbers rbx, which LLVM reserves on this target — save/restore
    // it inside the asm and hand the value out through an allocated reg.
    let ebx_out: u32;
    let d: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x80000001",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx_out,
            lateout("eax") _,
            lateout("ecx") _,
            lateout("edx") d,
            options(nostack)
        );
    }
    let _ = ebx_out;
    d & (1 << 26) != 0 // PDPE1GB
}

/// Build the kernel root and switch to it.
///
/// CEP: CEP-1 | Complete
/// Cost: one-time boot path; O(low-map entries + 1).
/// Fail: panics on allocator exhaustion (cannot continue without paging).
/// Assumes: called with the bootloader's page tables active; every frame
///          it allocates stays reachable through the NEW root's shared
///          windows (low identity covers the boot structures, HHDM covers
///          all served frames).
pub fn init() {
    let root = phys::alloc(PageClass::General)
        .unwrap_or_else(|| panic_str("pagemap: root alloc failed"));

    // --- PML4[0]: low identity, 512 MiB via 2 MiB pages -------------------
    let pd_low = phys::alloc(PageClass::General)
        .unwrap_or_else(|| panic_str("pagemap: low PD alloc failed"));
    unsafe {
        table(root)[0] = pd_low | PTE_P | PTE_W;
        let pd = table(pd_low);
        for i in 0..256usize {
            pd[i] = (i as u64) * (2 << 20) | PTE_P | PTE_W | PTE_PS;
        }
    }

    // --- PML4[256]: HHDM ---------------------------------------------------
    let pdpt_hh = phys::alloc(PageClass::General)
        .unwrap_or_else(|| panic_str("pagemap: HHDM PDPT alloc failed"));
    unsafe {
        table(root)[256] = pdpt_hh | PTE_P | PTE_W;
        if cpu_has_1g_pages() {
            // One 1 GiB page covers all served RAM (≤ 512 MiB ceiling).
            table(pdpt_hh)[0] = 0 | PTE_P | PTE_W | PTE_PS;
        } else {
            // Fallback: 2 MiB pages across the service ceiling.
            for i in 0..((phys::SERVICE_CEILING / (2 << 20)) as usize) {
                table(pdpt_hh)[i] = (i as u64) * (2 << 20) | PTE_P | PTE_W | PTE_PS;
            }
        }
    }

    // The per-task windows (SHM/PRIV) start EMPTY in the kernel root: the
    // kernel touches shared/private windows only through task roots (or
    // via the HHDM).
    unsafe {
        KERNEL_ROOT = root;
    }
    switch_cr3(root);
    serial::print(format_args!(
        "[mm] paging live: root {:#x}, HHDM via {}, low identity 512 MiB\n",
        root,
        if cpu_has_1g_pages() { "1 GiB page" } else { "2 MiB pages" }
    ));
}

/// Physical root of the kernel's own address space.
#[allow(dead_code)] // audit API: the fast-path milestone reads the root directly
/// Physical root of the kernel's own address space.
/// CEP: CEP-1 | Complete
/// Cost: O(1) read.
/// Fail: 0 before `init()` (callers init first by construction).
pub fn kernel_root() -> u64 {
    unsafe { KERNEL_ROOT }
}

/// The currently loaded CR3 root (write-through of every switch).
/// CEP: CEP-1 | Complete
/// Cost: O(1) read.
/// Fail: stale only if someone loads CR3 outside this module (none do —
///       Law: all CR3 writes go through switch_cr3).
pub fn current_cr3() -> u64 {
    unsafe { CURRENT_CR3 }
}

/// Load CR3 (full TLB flush — the Phase-2 revocation-safety baseline).
/// CEP: CEP-1 | Complete
/// Cost: one mov; hardware flush.
/// Fail: cannot fail.
#[inline]
pub fn switch_cr3(root: u64) {
    unsafe {
        core::arch::asm!("mov cr3, rax", in("rax") root, options(nostack, preserves_flags));
        CURRENT_CR3 = root;
    }
}

/// Create a fresh task root: its own PML4 with the shared windows
/// (PML4[0] low identity + PML4[256] HHDM) pointing at the SAME subtrees
/// as the kernel root, and empty per-task windows.
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) (two PML4 entry copies).
/// Fail: Err on allocator exhaustion.
pub fn new_task_root() -> Result<u64, &'static str> {
    let root = phys::alloc(PageClass::General).ok_or("pagemap: task root alloc failed")?;
    unsafe {
        let kr = table(KERNEL_ROOT);
        let tr = table(root);
        // Shared subtrees: low identity + HHDM. These point at frames the
        // kernel owns and never frees — sharing is by construction safe.
        tr[0] = kr[0];
        tr[256] = kr[256];
    }
    Ok(root)
}

/// Invalidate one virtual page in the CURRENT root's TLB. Required after
/// any PTE flag change or unmap on the root that is currently loaded —
/// otherwise the CPU keeps serving the stale translation (observed in
/// v0.5.0 bring-up: post-transfer write-demotion and post-revocation
/// denial both silently passed until the invlpg was added).
///
/// For OTHER roots no invalidation is needed in the Phase-2 model: every
/// CR3 load fully flushes the TLB, so the stale entries die on the owner's
/// next scheduling.
/// CEP: CEP-1 | Complete
/// Cost: one instruction.
#[inline]
pub fn invlpg_current(vaddr: u64) {
    unsafe {
        core::arch::asm!("invlpg [rax]", in("rax") vaddr, options(nostack));
    }
}

/// If `root` is the currently loaded CR3, invalidate `vaddr` in the TLB.
#[inline]
fn invalidate_if_current(root: u64, vaddr: u64) {
    if root == current_cr3() {
        invlpg_current(vaddr);
    }
}

/// Map one 4 KiB page `vaddr → phys_frame` in the given root, creating
/// intermediate tables as needed.
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) bounded walk; ≤ 3 table allocations on first touch of a
///       window.
/// Fail: Err on a populated PTE (remapping authority is explicit, never
///       silent) or allocator exhaustion.
pub fn map_page(root: u64, vaddr: u64, phys_frame: u64, write: bool) -> Result<(), &'static str> {
    if vaddr % PAGE_SIZE != 0 || phys_frame % PAGE_SIZE != 0 {
        return Err("pagemap: unaligned map");
    }
    let flags = PTE_P | if write { PTE_W } else { 0 };
    unsafe {
        let pml4 = table(root);
        let e4 = pml4[idx4(vaddr)];
        let pdpt_phys = if e4 & PTE_P != 0 {
            e4 & !0xFFF
        } else {
            let f = phys::alloc(PageClass::General).ok_or("pagemap: PDPT alloc failed")?;
            pml4[idx4(vaddr)] = f | PTE_P | PTE_W;
            f
        };
        let pdpt = table(pdpt_phys);
        let e3 = pdpt[idx3(vaddr)];
        if e3 & PTE_P != 0 {
            leaf_check(e3, "PDPT")?;
        }
        let pd_phys = if e3 & PTE_P != 0 {
            e3 & !0xFFF
        } else {
            let f = phys::alloc(PageClass::General).ok_or("pagemap: PD alloc failed")?;
            pdpt[idx3(vaddr)] = f | PTE_P | PTE_W;
            f
        };
        let pd = table(pd_phys);
        let e2 = pd[idx2(vaddr)];
        if e2 & PTE_P != 0 {
            leaf_check(e2, "PD")?;
        }
        let pt_phys = if e2 & PTE_P != 0 {
            e2 & !0xFFF
        } else {
            let f = phys::alloc(PageClass::General).ok_or("pagemap: PT alloc failed")?;
            pd[idx2(vaddr)] = f | PTE_P | PTE_W;
            f
        };
        let pt = table(pt_phys);
        if pt[idx1(vaddr)] & PTE_P != 0 {
            return Err("pagemap: PTE already populated");
        }
        pt[idx1(vaddr)] = phys_frame | flags;
    }
    Ok(())
}

/// Rewrite the flags of an existing PTE (used by the zero-copy transfer:
/// demoting the sender's mapping to read-only).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: Err if the page is not mapped (demotion of nothing is a bug).
pub fn reflag_page(root: u64, vaddr: u64, write: bool) -> Result<(), &'static str> {
    let flags = PTE_P | if write { PTE_W } else { 0 };
    unsafe {
        let pml4 = table(root);
        let e4 = pml4[idx4(vaddr)];
        if e4 & PTE_P == 0 {
            return Err("pagemap: reflag: PML4 empty");
        }
        let pdpt = table(e4 & !0xFFF);
        let e3 = pdpt[idx3(vaddr)];
        if e3 & PTE_P == 0 {
            return Err("pagemap: reflag: PDPT empty");
        }
        leaf_check(e3, "reflag PDPT")?;
        let pd = table(e3 & !0xFFF);
        let e2 = pd[idx2(vaddr)];
        if e2 & PTE_P == 0 {
            return Err("pagemap: reflag: PD empty");
        }
        leaf_check(e2, "reflag PD")?;
        let pt = table(e2 & !0xFFF);
        let e1 = pt[idx1(vaddr)];
        if e1 & PTE_P == 0 {
            return Err("pagemap: reflag: PTE empty");
        }
        pt[idx1(vaddr)] = (e1 & !PTE_W) | flags;
    }
    // TLB coherence: a demotion on the CURRENT root must evict the stale
    // RW translation, or the CPU keeps granting the old permission.
    invalidate_if_current(root, vaddr);
    Ok(())
}

/// Unmap a page (the CNode kill switch's hardware half: after this, the
/// task's next access to `vaddr` is a #PF).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: Err if the page was not mapped (revoking nothing is a bug).
pub fn unmap_page(root: u64, vaddr: u64) -> Result<(), &'static str> {
    unsafe {
        let pml4 = table(root);
        let e4 = pml4[idx4(vaddr)];
        if e4 & PTE_P == 0 {
            return Err("pagemap: unmap: PML4 empty");
        }
        let pdpt = table(e4 & !0xFFF);
        let e3 = pdpt[idx3(vaddr)];
        if e3 & PTE_P == 0 {
            return Err("pagemap: unmap: PDPT empty");
        }
        leaf_check(e3, "unmap PDPT")?;
        let pd = table(e3 & !0xFFF);
        let e2 = pd[idx2(vaddr)];
        if e2 & PTE_P == 0 {
            return Err("pagemap: unmap: PD empty");
        }
        leaf_check(e2, "unmap PD")?;
        let pt = table(e2 & !0xFFF);
        if pt[idx1(vaddr)] & PTE_P == 0 {
            return Err("pagemap: unmap: PTE empty");
        }
        pt[idx1(vaddr)] = 0;
    }
    // TLB coherence: an unmap on the CURRENT root must evict the stale
    // translation, or the revoked task keeps reading through it.
    invalidate_if_current(root, vaddr);
    // Full-flush CR3 model: the revoked task's stale TLB entries also die
    // on its next CR3 load (no PCID in Phase 2 — mm/mod.rs scope notes).
    Ok(())
}

/// Whether `vaddr` is mapped in `root` (audit helper; O(1)).
/// Whether `vaddr` has a 4 KiB mapping in `root` (audit helper; O(1)).
/// CEP: CEP-1 | Complete
/// Cost: O(1) bounded walk, read-only.
/// Fail: false for absent mappings AND for leaf entries (2 MiB/1 GiB
///       pages are not 4 KiB mappings — callers use per-task windows).
#[allow(dead_code)] // audit API: exercised by Phase-3 revocation audits
pub fn is_mapped(root: u64, vaddr: u64) -> bool {
    unsafe {
        let pml4 = table(root);
        let e4 = pml4[idx4(vaddr)];
        if e4 & PTE_P == 0 {
            return false;
        }
        let pdpt = table(e4 & !0xFFF);
        let e3 = pdpt[idx3(vaddr)];
        if e3 & PTE_P == 0 || e3 & PTE_PS != 0 {
            return false;
        }
        let pd = table(e3 & !0xFFF);
        let e2 = pd[idx2(vaddr)];
        if e2 & PTE_P == 0 || e2 & PTE_PS != 0 {
            return false;
        }
        let pt = table(e2 & !0xFFF);
        pt[idx1(vaddr)] & PTE_P != 0
    }
}

#[cold]
fn panic_str(msg: &str) -> ! {
    crate::panic_str("pagemap: ", msg)
}
