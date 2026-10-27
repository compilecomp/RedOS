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
//! Revocation model: unmapping from a task's root invalidates the TLB
//! translation — `invlpg` on the current root, `invpcid` (type 2,
//! root-tagged) on an inactive root when PCID is active, or the full
//! flush of the next CR3 load in the no-PCID baseline (mm/mod.rs). The
//! idt.rs probe protocol turns hardware traps into named denials.
//!
//! v0.8.0 additions: user/nx PTE bits (ring 3 + W^X), PCID/invpcid (the
//! measured context-switch optimization — enabled ONLY as the pair,
//! because noflush CR3 loads are only revocation-safe when stale entries
//! can be invalidated precisely), per-task user code/stack windows, and
//! `protect_kernel_text` (image-wide W^X: kernel text loses W).
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
/// Compositor screen window (PML4[230]) — the compositor's composed
/// output; NO app root ever maps it (the glass wall's other direction).
pub const GLASS_SCREEN: u64 = 0x0000_7300_0000_0000;
/// User code window (PML4[240]): ELF64 program images load here. User
/// VAs live in dedicated PML4 slots so a validated range check is a
/// TOP-LEVEL check — a crafted p_vaddr outside the window is refused
/// before any walk (elf.rs).
pub const USER_CODE_BASE: u64 = 0x0000_7800_0000_0000;
/// User stack window (PML4[248]); task slot i's stack top is
/// `USER_STACK_BASE + i * USER_STACK_STRIDE` (16 KiB mapped, guard-banded
/// by the unmapped VAs around it).
pub const USER_STACK_BASE: u64 = 0x0000_7C00_0000_0000;
pub const USER_STACK_STRIDE: u64 = 1 << 20;

const PML4_USER_CODE: usize = (USER_CODE_BASE >> 39) as usize & 0x1FF; // 240
const PML4_USER_STACK: usize = (USER_STACK_BASE >> 39) as usize & 0x1FF; // 248
const _: () = assert!(PML4_USER_CODE != PML4_USER_STACK);
const _: () = assert!(USER_STACK_BASE < 0x0000_8000_0000_0000);

const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;
const PTE_PS: u64 = 1 << 7;
/// Execute-disable (requires EFER.NXE = 1 — set by syscall::init_msr
/// before any NX-bearing PTE is ever translated).
const PTE_NX: u64 = 1 << 63;

// --- PCID / invpcid (v0.8.0 measured optimization) ---------------------------

static mut PCID_ACTIVE: bool = false;
/// Kernel root's PCID tag (1; 0 is avoided — CR3 loads of PCID 0 with
/// bit63 set are UNDEFINED-behavior territory per SDM Vol.3 4.10.1).
const KERNEL_PCID: u16 = 1;
static mut NEXT_PCID: u16 = KERNEL_PCID + 1;
/// Root → PCID registry (roots are frame-aligned; ≤ MAX_TASKS + 1 roots
/// exist; a linear scan of 14 entries beats a map for this scale).
static mut ROOT_PCID: [(u64, u16); 16] = [(0, 0); 16];
static mut ROOT_PCID_N: usize = 0;

const ROOT_PCID_CAP: usize = 16;

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

/// CPUID leaf 1 ECX bit 17: Process Context Identifiers.
/// CEP: CEP-1 | Complete
/// Cost: one cpuid.
/// Fail: cannot fail (returns the capability bit).
fn cpu_has_pcid() -> bool {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            lateout("ecx") ecx,
            lateout("eax") _,
            lateout("edx") _,
            options(nostack)
        );
    }
    ecx & (1 << 17) != 0
}

/// CPUID leaf 7 subleaf 0 EBX bit 10: INVPCID instruction.
/// CEP: CEP-1 | Complete
/// Cost: one cpuid.
/// Fail: cannot fail.
fn cpu_has_invpcid() -> bool {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            lateout("eax") _,
            lateout("ecx") _,
            lateout("edx") _,
            options(nostack)
        );
    }
    ebx & (1 << 10) != 0
}

/// Whether PCID-aware (noflush) CR3 loads are live. TRUE only when the
/// CPU has BOTH PCID and INVPCID: the noflush switch is only revocation-
/// safe if stale translations can be invalidated precisely (see the
/// invalidation paths below). Without the pair we keep the full-flush
/// baseline — the safe default, honestly measured either way.
/// CEP: CEP-1 | Complete
/// Cost: one load. Fail: cannot fail.
pub fn pcid_active() -> bool {
    unsafe { PCID_ACTIVE }
}

/// Enable the PCID + INVPCID pair (CR4.PGE first — the SDM's constraint
/// for setting CR4.PCIDE — then PCIDE). Registers the kernel root under
/// its PCID tag.
/// CEP: CEP-1 | Complete
/// Cost: one-time boot path.
/// Fail: cannot fail (absent features leave the baseline untouched).
/// Assumes: called once, after pagemap::init (the kernel root exists).
pub fn init_pcid() {
    let has_p = cpu_has_pcid();
    let has_i = cpu_has_invpcid();
    if !has_p || !has_i {
        unsafe { PCID_ACTIVE = false };
        serial::print(format_args!(
            "[mm] PCID/INVPCID: {} / {} — full-flush baseline kept (safe)\n",
            if has_p { "yes" } else { "no" },
            if has_i { "yes" } else { "no" }
        ));
        return;
    }
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {0}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= 1 << 7; // PGE (prerequisite for PCIDE)
        core::arch::asm!("mov cr4, {0}", in(reg) cr4, options(nostack, preserves_flags));
        let mut cr4b: u64;
        core::arch::asm!("mov {0}, cr4", out(reg) cr4b, options(nomem, nostack, preserves_flags));
        cr4b |= 1 << 17; // PCIDE
        core::arch::asm!("mov cr4, {0}", in(reg) cr4b, options(nostack, preserves_flags));
        PCID_ACTIVE = true;
        register_root_pcid(kernel_root(), KERNEL_PCID);
    }
    serial::print(format_args!(
        "[mm] PCID+INVPCID live: kernel root pcid {}, noflush root switches armed\n",
        KERNEL_PCID
    ));
}

/// Bind a physical root to a PCID tag (call once per new root).
/// CEP: CEP-1 | Complete
/// Cost: O(1) append (table of 16).
/// Fail: panics when the registry is full — capacity is bound by
///       MAX_TASKS + 1 and MUST NOT wrap silently (PCID reuse without a
///       flush serves stale translations: a revocation-safety hole).
fn register_root_pcid(root: u64, pcid: u16) {
    unsafe {
        if ROOT_PCID_N >= ROOT_PCID_CAP {
            panic_str("PCID registry exhausted — increase ROOT_PCID (no silent tag reuse)");
        }
        ROOT_PCID[ROOT_PCID_N] = (root, pcid);
        ROOT_PCID_N += 1;
    }
}

/// The PCID tag bound to `root` (0 = unregistered: flush-mode loads).
/// CEP: CEP-1 | Complete
/// Cost: O(REGISTRY_N) scan (≤ 16 entries).
/// Fail: cannot fail (0 is the honest answer for unregistered roots).
pub fn pcid_of(root: u64) -> u16 {
    unsafe {
        for i in 0..ROOT_PCID_N {
            if ROOT_PCID[i].0 == root {
                return ROOT_PCID[i].1;
            }
        }
    }
    0
}

/// Allocate the next free PCID tag for a fresh task root.
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: returns 0 (flush-mode) once the 12-bit space nears exhaustion —
///       a NAMED degradation, never a silent tag reuse.
pub fn alloc_pcid() -> u16 {
    unsafe {
        if NEXT_PCID >= 0xFFF {
            return 0; // flush-mode fallback; documented, safe
        }
        let p = NEXT_PCID;
        NEXT_PCID += 1;
        p
    }
}

/// INVPCID type 0 (individual-address): invalidate the translation of
/// `vaddr` for `pcid` only.
/// CEP: CEP-1 | Complete
/// Cost: one instruction.
/// Fail: cannot fail (type 0 is a fixed input; the CPU enforces the
///       descriptor's canonical checks for us).
/// Assumes: safe regardless of PCID_ACTIVE — on an inactive system every
///          CR3 load flushes everything, so the extra invalidate is moot.
#[inline]
fn invpcid_addr(pcid: u16, vaddr: u64) {
    let desc: [u64; 2] = [(pcid as u64) | (vaddr & !0xFFF), 0];
    unsafe {
        core::arch::asm!(
            // INVPCID (66 0F 38 82 /r): the TYPE travels in the modrm
            // reg field (EAX here), the 128-bit descriptor at [rdx].
            // (GAS refuses the `invpcid eax, [rdx]` spelling, so the
            // 66-prefixed encoding is emitted by hand — verified against
            // objdump: 66 0f 38 82 02.) Type 0 = individual-address.
            // REVIEW FIX (v0.8.0): EAX was previously a clobber output —
            // the type operand read uninitialized EAX (UB: a leftover
            // value >= 4 faults with #UD on exactly the machines where
            // PCID arms; 1-3 over-invalidate).
            ".byte 0x66, 0x0F, 0x38, 0x82, 0x02",
            in("eax") 0u32,
            in("rdx") desc.as_ptr(),
            options(nostack)
        );
    }
}

/// Load CR3 with the root's PCID tag. noflush = keep the incoming root's
/// cached translations (the optimization: a root switch becomes ~free).
/// Revocation safety contract: EVERY unmap/reflag on a non-current root
/// invalidates via invpcid type 0 (below), so noflush loads never resurrect a
/// dead translation. pcid 0 / inactive PCID = plain CR3 load (full flush).
/// CEP: CEP-1 | Complete
/// Cost: one mov (flush) or one mov + the retained TLB (noflush).
/// Fail: cannot fail.
#[inline]
pub fn switch_cr3_pcid(root: u64, pcid: u16, noflush: bool) {
    let mut val = root;
    if pcid_active() && pcid != 0 {
        val |= pcid as u64;
        if noflush {
            val |= 1 << 63;
        }
    }
    unsafe {
        core::arch::asm!("mov cr3, rax", in("rax") val, options(nostack, preserves_flags));
        CURRENT_CR3 = root;
    }
}

fn cpu_has_1g_pages() -> bool {
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
    unsafe {
        // STRUCTURAL NOTE (the v0.8.0 W^X milestone caught this): the
        // walk under PML4[0] is PML4 -> PDPT -> PD -> PT. The v0.5.0
        // draft pointed PML4[0] straight at a table of 2 MiB entries —
        // which the CPU reads as a PDPT whose PS bit means **1 GiB** —
        // so the whole low identity was accidentally ONE giant RW 1 GiB
        // page (it "worked" because entry 0's address field is 0). The
        // text could never be write-protected and every "2 MiB leaf"
        // edit below PML4[0] edited the wrong level. Fixed here: the
        // PDPT level is explicit, the PD holds the 2 MiB leaves, and the
        // kernel-image leaf is a 4 KiB PT with the text RO FROM BIRTH
        // (no large-page entry for the region ever exists, so the W^X
        // verification needs no TLB eviction dance at all).
        let pdpt_low = phys::alloc(PageClass::General)
            .unwrap_or_else(|| panic_str("pagemap: low PDPT alloc failed"));
        let pd_low = phys::alloc(PageClass::General)
            .unwrap_or_else(|| panic_str("pagemap: low PD alloc failed"));
        table(root)[0] = pdpt_low | PTE_P | PTE_W;
        // PDPT[0] covers VAs [0, 1 GiB).
        table(pdpt_low)[0] = pd_low | PTE_P | PTE_W;
        let pd = table(pd_low);
        // 2 MiB leaves: the correct level for PS=1 with 2 MiB granularity.
        for i in 0..256usize {
            pd[i] = (i as u64) * (2 << 20) | PTE_P | PTE_W | PTE_PS;
        }
        // The kernel-image leaf ([0x200000, 0x400000)) is a 4 KiB PT, and
        // the text span is read-only FROM BIRTH: the first walk through
        // this root already sees RO text (the W^X tenet, image-wide).
        let img_pt = phys::alloc(PageClass::General)
            .unwrap_or_else(|| panic_str("pagemap: image PT alloc failed"));
        pd[1] = img_pt | PTE_P | PTE_W; // PS cleared: 4 KiB granularity
        let t0 = &__text_start as *const u8 as u64;
        let t1 = &__text_end as *const u8 as u64;
        let img_base = 0x20_0000u64;
        for i in 0..512usize {
            let frame = img_base + (i as u64) * PAGE_SIZE;
            table(img_pt)[i] = frame | PTE_P | PTE_W;
        }
        let first = (t0 - img_base) / PAGE_SIZE;
        let last = (t1 - img_base + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in first..last {
            table(img_pt)[i as usize] &= !PTE_W; // text: RO from birth
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
    // PCID tag for the noflush switch path (0 = flush-mode fallback).
    register_root_pcid(root, alloc_pcid());
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

/// (superseded by `invalidate_root` — kept for the doc trail; unused)
/// If `root` is the currently loaded CR3, invalidate `vaddr` in the TLB.
#[allow(dead_code)]
#[inline]
fn invalidate_if_current(root: u64, vaddr: u64) {
    if root == current_cr3() {
        invlpg_current(vaddr);
    }
}

/// Map one 4 KiB page `vaddr → phys_frame` in the given root, creating
/// intermediate tables as needed (supervisor wrapper over `map_page_ex`).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) bounded walk; ≤ 3 table allocations on first touch of a
///       window.
/// Fail: Err on a populated PTE (remapping authority is explicit, never
///       silent) or allocator exhaustion.
pub fn map_page(root: u64, vaddr: u64, phys_frame: u64, write: bool) -> Result<(), &'static str> {
    map_page_ex(root, vaddr, phys_frame, write, false, false)
}

/// The full-flag map: `user` sets PTE.U (ring 3 may translate), `nx`
/// sets PTE.NX (EFER.NXE required — see syscall.rs). W^X discipline for
/// user images lives at the CALLER (elf.rs): text = !write && !nx,
/// data/stack = write && nx.
///
/// U-PROPAGATION: the MMU requires PTE.U at EVERY level of the walk — a
/// user leaf under supervisor intermediates still faults (observed in
/// v0.8.0 bring-up: the entry fetch died with e=0x15). When `user` is
/// set, every intermediate entry on the walk gets U ored in — including
/// already-present ones (a supervisor mapping may have created them).
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) bounded walk; ≤ 3 table allocations on first touch.
/// Fail: Err on a populated PTE or allocator exhaustion.
pub fn map_page_ex(
    root: u64,
    vaddr: u64,
    phys_frame: u64,
    write: bool,
    user: bool,
    nx: bool,
) -> Result<(), &'static str> {
    if vaddr % PAGE_SIZE != 0 || phys_frame % PAGE_SIZE != 0 {
        return Err("pagemap: unaligned map");
    }
    let mut flags = PTE_P | if write { PTE_W } else { 0 };
    if user {
        flags |= PTE_U;
    }
    if nx {
        flags |= PTE_NX;
    }
    let u_flag = if user { PTE_U } else { 0 };
    unsafe {
        let pml4 = table(root);
        let e4 = pml4[idx4(vaddr)];
        let pdpt_phys = if e4 & PTE_P != 0 {
            if u_flag != 0 && e4 & PTE_U == 0 {
                pml4[idx4(vaddr)] = e4 | PTE_U; // U-propagation (see docs)
            }
            e4 & !0xFFF
        } else {
            let f = phys::alloc(PageClass::General).ok_or("pagemap: PDPT alloc failed")?;
            pml4[idx4(vaddr)] = f | PTE_P | PTE_W | u_flag;
            f
        };
        let pdpt = table(pdpt_phys);
        let e3 = pdpt[idx3(vaddr)];
        let pd_phys = if e3 & PTE_P != 0 {
            leaf_check(e3, "PDPT")?;
            if u_flag != 0 && e3 & PTE_U == 0 {
                pdpt[idx3(vaddr)] = e3 | PTE_U;
            }
            e3 & !0xFFF
        } else {
            let f = phys::alloc(PageClass::General).ok_or("pagemap: PD alloc failed")?;
            pdpt[idx3(vaddr)] = f | PTE_P | PTE_W | u_flag;
            f
        };
        let pd = table(pd_phys);
        let e2 = pd[idx2(vaddr)];
        let pt_phys = if e2 & PTE_P != 0 {
            leaf_check(e2, "PD")?;
            if u_flag != 0 && e2 & PTE_U == 0 {
                pd[idx2(vaddr)] = e2 | PTE_U;
            }
            e2 & !0xFFF
        } else {
            let f = phys::alloc(PageClass::General).ok_or("pagemap: PT alloc failed")?;
            pd[idx2(vaddr)] = f | PTE_P | PTE_W | u_flag;
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
    invalidate_root(root, vaddr);
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
    invalidate_root(root, vaddr);
    // PCID model: an INACTIVE root's stale entries die at invalidate time
    // (invpcid below) — noflush CR3 loads can then never resurrect them
    // (proof/Fastpath.thy: tlb_ok obligation). Flush-mode baseline: the
    // full flush on the owner's next CR3 load.
    Ok(())
}

/// Invalidate one page's translation for `root`'s address space: invlpg
/// when the root is loaded, invpcid(type 2, root tag) when PCID is active
/// and the root is inactive, and nothing when neither holds (flush-mode
/// baseline: the owner's next CR3 load is a full flush).
/// CEP: CEP-1 | Complete
/// Cost: one instruction.
/// Fail: cannot fail.
#[inline]
fn invalidate_root(root: u64, vaddr: u64) {
    if root == current_cr3() {
        invlpg_current(vaddr);
    } else if pcid_active() {
        let pcid = pcid_of(root);
        if pcid != 0 {
            invpcid_addr(pcid, vaddr);
        }
    }
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

// --- Image-wide W^X (v0.8.0 paging item promised at v0.7.0) ------------------

extern "C" {
    /// Linker-provided kernel text bounds (linker.ld).
    static __text_start: u8;
    /// Linker-provided kernel text bounds (linker.ld).
    static __text_end: u8;
}

/// Verify the image-wide W^X (the demotion happened at `init` — see the
/// pagemap::init notes): probe-write a text byte; the MMU must deny it.
/// Returns true when the text is genuinely read-only.
///
/// CEP: CEP-1 | Complete
/// Cost: one probe.
/// Fail: returns false (the caller prints the FAIL line — a writable
///       text is a build-ordering regression, never silent).
/// Assumes: called after pagemap::init; interrupts disabled.
pub fn verify_kernel_text_ro() -> bool {
    let t0 = unsafe { &__text_start as *const u8 as u64 };
    !crate::mm::idt::probe_write(t0 + 8, 0x9999)
}
