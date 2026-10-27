//! RedOS kernel — zero-copy shared memory + the CNode kill switch
//! (Pillar 2, "Zero-Copy Shared Memory" + "Instant Revocation").
//!
//! The data path (docs/ARCHITECTURE.md §Zero-Copy Shared Memory):
//!
//! 1. `create()` allocates a physically contiguous run of frames, class
//!    `Shared`, and hands the creator a read-write mapping at the task's
//!    `SHM_BASE` window (PML4[192], one 1 GiB slot per block id).
//! 2. The producer writes the payload **through its own mapping** — the
//!    kernel never touches the bytes (blindness is preserved: the router
//!    moves a 24-byte descriptor, not the payload).
//! 3. `transfer()` implements the handoff semantics: the sender's mapping
//!    is demoted to READ-ONLY (write-demotion on send), the receiver is
//!    mapped READ-WRITE, and the receiver receives a *capability token*
//!    (a CNode slot naming the block) — "the data never moves; only the
//!    right to view it is transferred." Ordering: demote → mint → map →
//!    commit. Under the cooperative single-task model no observer can run
//!    between these steps; a failure after the mint rolls the mint back,
//!    so the block returns to the untransferred state (retry-able, and no
//!    mapping ever exists without its capability).
//! 4. `revoke()` is the kill switch: the capability slot is zeroed AND the
//!    receiver's page-table entries are torn down AND the block is marked
//!    revoked — after which NO kernel path will ever map it again
//!    (`map_for` and `transfer` both refuse; this is the kernel half of
//!    the monotonicity that proof/Revoke.thy models as the `sdead`
//!    registry). The receiver's next access is a hardware #PF (caught by
//!    the idt.rs probe protocol and turned into a generic "Access
//!    Denied"). No policy check survives — the MMU itself enforces the
//!    revocation.
//!
//! CEP: CEP-1 | Complete (Phase 2 scope: ≤ 4 blocks, 2 pages each)
//! Cost: create O(pages); transfer O(pages) PTE writes (no payload copy —
//!       that is the entire point); revoke O(1) + O(pages) PTE teardown.
//! Fail: every operation validates the capability and mapping state and
//!       fails with named errors; a revoked block cannot be re-mapped
//!       (revocation is monotone within a boot, enforced by the `revoked`
//!       flag checked by map_for/transfer).
//! Assumes: task roots exist before mapping into them (see task.rs CR3
//!          lifecycle); single CPU, cooperative scheduling.

use crate::cap::{self, rights};
use crate::mm::pagemap::{self, SHM_BASE, SHM_STRIDE};
use crate::mm::phys::{self, PageClass, PAGE_SIZE};

pub const MAX_BLOCKS: usize = 4;
/// Demo-scale block size (8 KiB). The manifest's resource ceilings govern
/// the production sizes (Pillar 1) — Phase 2 fixes the constant.
pub const BLOCK_PAGES: usize = 2;

/// One zero-copy shared-memory block. Copy is derived ONLY for the
/// const-initialized static table; instances are never copied at runtime.
#[derive(Clone, Copy)]
pub struct Block {
    pub phys: u64,
    pub pages: usize,
    /// The root the RECEIVER's window is mapped into after `transfer`.
    /// The sender's read-only view is not tracked separately: it is
    /// demoted at transfer time and dies with the sender's task.
    pub mapped_in: Option<u64>,
    /// Whether the block has been transferred (sender demoted to RO;
    /// receiver holds the capability). One-way: a transferred block is
    /// never transferable again.
    pub transferred: bool,
    /// Monotone revocation registry (the kernel half of Revoke.thy's
    /// `sdead`): once true, NO kernel path maps this block again.
    pub revoked: bool,
}

static mut BLOCKS: [Option<Block>; MAX_BLOCKS] = [None; MAX_BLOCKS];

/// CEP: CEP-1 | Complete
/// Cost: O(1) slot scan + O(pages) allocation + O(pages) zeroing.
/// Fail: named errors on slot exhaustion or no contiguous run (checked
///       BEFORE the allocation, so no frames are ever orphaned).
/// Does NOT map anything yet — the producer maps its view explicitly.
pub fn create(pages: usize) -> Result<usize, &'static str> {
    if pages == 0 {
        return Err("shm: zero-page block");
    }
    let blocks = blocks();
    let id = (0..MAX_BLOCKS)
        .find(|&i| blocks[i].is_none())
        .ok_or("shm: block table full")?;
    let phys = phys::alloc_contig(PageClass::Shared, pages)
        .ok_or("shm: no contiguous shared run")?;
    blocks[id] = Some(Block {
        phys,
        pages,
        mapped_in: None,
        transferred: false,
        revoked: false,
    });
    Ok(id)
}

/// The virtual address of block `id` in whatever root it is mapped into.
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: cannot fail.
pub fn vaddr_of(id: usize) -> u64 {
    SHM_BASE + (id as u64) * SHM_STRIDE
}

/// Map block `id` into `root` with the given write permission.
/// CEP: CEP-1 | Complete
/// Cost: O(pages).
/// Fail: named errors (revoked block, unknown block, PTE conflicts).
pub fn map_for(root: u64, id: usize, write: bool) -> Result<(), &'static str> {
    let (phys, pages) = {
        let b = blocks()[id]
            .as_ref()
            .ok_or("shm: map of unknown block")?;
        if b.revoked {
            return Err("shm: block revoked — no kernel path may map it again");
        }
        (b.phys, b.pages)
    };
    let base = vaddr_of(id);
    for p in 0..pages {
        pagemap::map_page(root, base + (p as u64) * PAGE_SIZE, phys + (p as u64) * PAGE_SIZE, write)?;
    }
    blocks()[id].as_mut().unwrap().mapped_in = Some(root);
    Ok(())
}

/// The zero-copy handoff: demote the sender's mapping to read-only,
/// mint the receiver's capability, map the receiver read-write, and only
/// then commit the transfer. Rollback on failure keeps the invariants:
/// no mapping without a capability, no half-transferred state.
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) mint + O(pages) PTE writes. No payload bytes move.
/// Fail: named errors on unknown/revoked/already-transferred block or
///       table exhaustion (with the mint rolled back).
pub fn transfer(
    id: usize,
    sender_root: u64,
    receiver_root: u64,
    receiver_table: &mut cap::CTable,
) -> Result<usize, &'static str> {
    {
        let b = blocks()[id].as_mut().ok_or("shm: transfer of unknown block")?;
        if b.revoked {
            return Err("shm: block revoked — transfer refused");
        }
        if b.transferred {
            return Err("shm: block already transferred");
        }
    }
    // 1. Sender write-demotion (the "Read-Only" half of the dual-keyhole).
    let base = vaddr_of(id);
    let pages = blocks()[id].as_ref().ok_or("shm: transfer lost block")?.pages;
    for p in 0..pages {
        pagemap::reflag_page(sender_root, base + (p as u64) * PAGE_SIZE, false)?;
    }
    // 2. Receiver gets the capability token FIRST (the authority must
    //    exist before the mapping it authorizes)...
    let slot = receiver_table.mint_shm(id, rights::READ | rights::WRITE)?;
    // 3. ...then the read-write keyhole. On failure, roll the mint back —
    //    the block returns to untransferred (retry-able) and no mapping
    //    exists without its capability.
    if let Err(e) = map_for(receiver_root, id, true) {
        receiver_table.revoke(slot);
        // Sender demotion stands (harmless: the data is complete; the
        // sender's writes were done before the transfer call).
        return Err(e);
    }
    // 4. Commit.
    blocks()[id].as_mut().unwrap().transferred = true;
    Ok(slot)
}

/// The CNode kill switch: zero the capability slot, tear down the
/// receiver's PTEs, and mark the block revoked. After this returns, the
/// receiver's next access to the window is a hardware #PF — the MMU
/// enforces what the Permission Tracker ordered — and NO kernel path
/// (map_for/transfer) will ever map the block again.
///
/// CEP: CEP-1 | Complete
/// Cost: O(1) cap zero + O(pages) PTE teardown.
/// Fail: Err if the capability does not name `id` (forged/dangling use);
///       revocation itself is monotone — a revoked block stays revoked.
pub fn revoke(
    root: u64,
    table: &mut cap::CTable,
    slot: usize,
    id: usize,
) -> Result<(), &'static str> {
    // Validate the capability FIRST (a forged slot must fail named).
    table.lookup_shm(slot, id)?;
    {
        let b = blocks()[id].as_mut().ok_or("shm: revoke of unknown block")?;
        table.revoke(slot); // the CNode slot is zeroed (Kill Switch, step 1)
        b.mapped_in = None;
        b.revoked = true; // monotone: no re-map, ever (Revoke.thy sdead)
        let pages = b.pages;
        let base = vaddr_of(id);
        for p in 0..pages {
            pagemap::unmap_page(root, base + (p as u64) * PAGE_SIZE)?; // step 2
        }
    }
    Ok(())
}

/// Physical address of block (test/audit access via HHDM).
/// CEP: CEP-1 | Complete
/// Cost: O(1).
/// Fail: Err on unknown block (diagnostics must not silently fall back).
pub fn phys_of(id: usize) -> Result<u64, &'static str> {
    Ok(blocks()[id].as_ref().ok_or("shm: unknown block")?.phys)
}

#[allow(static_mut_refs)]
fn blocks() -> &'static mut [Option<Block>; MAX_BLOCKS] {
    unsafe { &mut *core::ptr::addr_of_mut!(BLOCKS) }
}

/// Glass-wall share (v0.8.0): map block `id` READ-ONLY into `viewer_root`
/// and mint a READ-only capability into the viewer's table. Unlike
/// `transfer`, the OWNER's mapping is untouched (it keeps drawing into
/// its window); the viewer gets glass — a read-only pane — and nothing
/// else. The `mapped_in` single-viewer note of `map_for` is deliberately
/// not consulted: two roots legitimately hold views of one block with
/// different permissions (owner RW, viewer RO) — that IS the glass wall.
///
/// CEP: CEP-1 | Complete
/// Cost: O(pages) PTE writes + one mint.
/// Fail: named errors (unknown/revoked block, mint exhaustion, PTE
///       conflicts). The mint is rolled back if the mapping fails.
pub fn share_ro(
    viewer_root: u64,
    viewer_caps: &mut crate::cap::CTable,
    id: usize,
) -> Result<usize, &'static str> {
    let (phys, pages) = {
        let b = blocks()[id]
            .as_ref()
            .ok_or("shm: share of unknown block")?;
        if b.revoked {
            return Err("shm: block revoked — no kernel path may map it again");
        }
        (b.phys, b.pages)
    };
    // Mint FIRST (rollback on map failure), then map read-only.
    let slot = viewer_caps.mint_shm(id, crate::cap::READ)?;
    let base = vaddr_of(id);
    for p in 0..pages {
        if let Err(e) = pagemap::map_page(viewer_root, base + (p as u64) * PAGE_SIZE, phys + (p as u64) * PAGE_SIZE, false) {
            viewer_caps.revoke(slot);
            return Err(e);
        }
    }
    Ok(slot)
}
