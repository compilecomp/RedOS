//! RedOS kernel — the Glass Wall: compositor read-only pixel buffers
//! (v0.8.0, Pillar 2/5).
//!
//! The display story with zero-ID isolation in mind:
//!
//! * **Painter (task P)** owns its window surface: a shared-memory block
//!   mapped READ-WRITE in P's root — P draws into it directly, no kernel
//!   copy, no syscall in the drawing path.
//! * **Compositor (task W)** sees exactly the glass: the SAME block
//!   mapped READ-ONLY in W's root (shm::share_ro — owner keeps RW, the
//!   viewer gets a pane). W composes the surface into its own private
//!   screen frame and presents.
//! * **The wall itself (MMU-proven, both directions):**
//!   - W probe-writes its surface view → DENIED (RO pane; content
//!     integrity belongs to the app that drew it);
//!   - W probe-reads P's private page → DENIED (#PF; the compositor's
//!     root never maps app-private memory — it cannot see behind the
//!     glass);
//!   - P probe-reads the compositor's screen → DENIED (the presented
//!     frame is W-private; apps cannot see the composition side).
//!
//! Scheduling-order independence: kmain wires W's root + screen via
//! `wire_compositor` BEFORE spawning W (a parked task's root must exist
//! before the painter can grant the pane — the grant targets
//! tasks[W].cr3 unconditionally). P builds its own root in its body; the
//! probe against P's private page only happens after P's ready signal,
//! so the page exists by then.
//!
//! This is the same per-root permission machinery the zero-copy transfer
//! uses (pagemap per-task windows), pointed at a display policy instead
//! of a data handoff. proof/Fastpath.thy models the visibility set: the
//! compositor's reachable pages = own private + granted RO panes, and
//! no command in the model can grow that set beyond a grant.
//!
//! CEP: CEP-1 | Complete
//! Cost: one shm block (2 pages), O(pages) maps, a pattern write, three
//!       probes, one 64-byte compose copy.
//! Fail: FAIL lines (CI-visible) for any assertion breach; panics on
//!       kernel-contract breaches (fail-fast).
//! Assumes: single CPU, cooperative scheduling; W parks in a byte recv
//!          BEFORE P sends (the mailbox path also covers the opposite
//!          order — both are safe by construction).

use crate::ipc::IpcSendError;
use crate::mm::idt;
use crate::mm::pagemap::{self, GLASS_SCREEN, PRIV_BASE};
use crate::mm::phys::{self, PageClass, PAGE_SIZE};
use crate::serial;
use crate::task::tasks;

/// The composed view the compositor samples (first 8 surface words —
/// enough to prove the pane carried the painter's pixels).
const SAMPLE_WORDS: usize = 8;

/// The pattern the painter draws (two alternating words — recognizable,
/// not self-symmetric at 8-byte granularity).
const PAT_A: u64 = 0x0DD1_7A11_5EED_F00D;
const PAT_B: u64 = 0x1337_C0DE_CAFE_BABE;

/// Pre-wire the compositor's address space (kmain, BEFORE spawning W):
/// fresh root + private screen frame mapped RW. Returns the root.
/// CEP: CEP-1 | Complete
/// Cost: one root alloc + one frame + O(1) maps.
/// Fail: named panics (allocation exhaustion is a boot failure).
pub fn wire_compositor(compositor_slot: usize) -> u64 {
    let root_w = pagemap::new_task_root()
        .unwrap_or_else(|e| crate::panic_str("W: task root: ", e));
    let screen = phys::alloc(PageClass::General)
        .unwrap_or_else(|| crate::panic_str("W: ", "screen frame exhausted"));
    pagemap::map_page(root_w, GLASS_SCREEN, screen, true)
        .unwrap_or_else(|e| crate::panic_str("W: map screen: ", e));
    tasks()[compositor_slot].cr3 = root_w;
    tasks()[compositor_slot].pcid = pagemap::pcid_of(root_w);
    root_w
}

/// Compositor entry (spawned by kmain with its cap slot as the arg).
/// CEP: CEP-1 | Complete
/// Cost: one blocked recv + probes + one 64-byte compose.
/// Fail: FAIL lines / named panics (scenario discipline).
pub fn compositor(me: usize, cap_glass: usize, ep_glass: usize) -> ! {
    let root_w = tasks()[me].cr3;
    if root_w == 0 {
        crate::panic_str("W: ", "root not wired (wire_compositor missing)");
    }
    pagemap::switch_cr3_pcid(root_w, tasks()[me].pcid, false);
    serial::print(format_args!(
        "[W] compositor root {:#x} live; private screen at {:#x}\n",
        root_w, GLASS_SCREEN
    ));

    // Park until the painter signals the surface is painted. Same
    // delivered-flag discipline as every byte-recv caller (the v0.3.0
    // lesson): a direct delivery fills our registered buffer BEFORE we
    // resume — consume it, never re-call recv.
    let mut buf = [0u8; 8];
    let n = loop {
        {
            let ts = crate::task::tasks();
            if ts[me].delivered {
                ts[me].delivered = false;
                break ts[me].recv_len;
            }
        }
        match crate::ipc::ipc_recv(
            me,
            crate::cap::table_of(me),
            cap_glass,
            ep_glass,
            buf.as_mut_ptr(),
            buf.len(),
        ) {
            Ok(n) => break n,
            Err(crate::ipc::IpcRecvError::Block) => crate::task::schedule_from(me),
            Err(crate::ipc::IpcRecvError::Contract(e)) => {
                crate::panic_str("W: surface recv contract: ", e)
            }
        }
    };
    serial::print(format_args!("[W] surface-ready signal ({} bytes)\n", n));

    // Read the glass: W's RO pane of the painter's surface (the block
    // id arrives through the scenario wiring — the pane itself was
    // granted by share_ro against THIS block).
    let surf = crate::shm::vaddr_of(glass_block()) as *const u64;
    let mut sample = [0u64; SAMPLE_WORDS];
    for (i, s) in sample.iter_mut().enumerate() {
        *s = unsafe { surf.add(i).read_volatile() };
    }
    let pattern_ok = sample[..SAMPLE_WORDS]
        .iter()
        .enumerate()
        .all(|(i, &v)| v == if i % 2 == 0 { PAT_A } else { PAT_B });

    // Compose into W's own screen (private RW — the presentation side).
    let scr = GLASS_SCREEN as *mut u64;
    for i in 0..SAMPLE_WORDS {
        unsafe { scr.add(i).write_volatile(sample[i]) };
    }
    let composed = unsafe { scr.add(0).read_volatile() } == PAT_A
        && unsafe { scr.add(SAMPLE_WORDS - 1).read_volatile() } == PAT_B;

    // --- The wall, direction 1: the pane is READ-ONLY to the viewer ----
    let pane_write = idt::probe_write(
        crate::shm::vaddr_of(glass_block()),
        0x0BAD_F00D_0000_0001,
    );

    // --- The wall, direction 2: app-private memory is invisible ---------
    // P's private page (PRIV_BASE exists only in P's root; W's root has
    // no translation there — the #PF probe turns it into a denial).
    let behind_glass = idt::probe_read(PRIV_BASE).is_some();

    if pattern_ok && composed && !pane_write && !behind_glass {
        serial::print(format_args!(
            "[W] surface read via RO pane (pattern intact), composed into private screen\n"
        ));
        serial::print(format_args!(
            "[W] pane write denied by MMU; painter-private probe denied by MMU\nREDOS GLASSWALL PASS\n"
        ));
    } else {
        serial::print(format_args!(
            "[W] FAIL: pattern_ok={} composed={} pane_write_denied={} private_read_denied={}\n",
            pattern_ok,
            composed,
            !pane_write,
            !behind_glass
        ));
    }
    serial::print(format_args!("[W] done\n"));
    crate::task::task_exit(me)
}

/// Painter entry (spawned by kmain with its cap slot as the arg).
/// CEP: CEP-1 | Complete
/// Cost: one root + one private frame + shm create/map + pattern writes.
/// Fail: FAIL lines / named panics (scenario discipline).
pub fn painter(me: usize, cap_glass: usize, ep_glass: usize) -> ! {
    let root_p = pagemap::new_task_root()
        .unwrap_or_else(|e| crate::panic_str("P: task root: ", e));
    // P-private page (the compositor's probe target — must NOT leak).
    let priv_frame = phys::alloc(PageClass::General)
        .unwrap_or_else(|| crate::panic_str("P: ", "private frame exhausted"));
    pagemap::map_page(root_p, PRIV_BASE, priv_frame, true)
        .unwrap_or_else(|e| crate::panic_str("P: map private: ", e));
    // Fill the private page through the HHDM (the kernel root has no
    // PRIV_BASE translation until the switch below).
    let pv = pagemap::hhdm_mut(priv_frame) as *mut u64;
    for k in 0..(PAGE_SIZE / 8) {
        unsafe { pv.add(k as usize).write_volatile(0x9901_55AA_5E5E_A11E) };
    }
    tasks()[me].cr3 = root_p;
    tasks()[me].pcid = pagemap::pcid_of(root_p);
    pagemap::switch_cr3_pcid(root_p, tasks()[me].pcid, false);
    serial::print(format_args!(
        "[P] painter root {:#x} live; private page at {:#x}\n",
        root_p, PRIV_BASE
    ));

    // Own the surface: create the block, map RW in P's root, draw.
    let block = crate::shm::create(crate::shm::BLOCK_PAGES)
        .unwrap_or_else(|e| crate::panic_str("P: shm create: ", e));
    crate::shm::map_for(root_p, block, true)
        .unwrap_or_else(|e| crate::panic_str("P: shm map RW: ", e));
    let surf = crate::shm::vaddr_of(block) as *mut u64;
    let words = crate::shm::BLOCK_PAGES * (PAGE_SIZE as usize / 8);
    for i in 0..words {
        let v = if i % 2 == 0 { PAT_A } else { PAT_B };
        unsafe { surf.add(i).write_volatile(v) };
    }
    serial::print(format_args!(
        "[P] painted surface block {} ({} words) via own RW mapping\n",
        block, words
    ));
    set_block(block);

    // Grant the compositor the glass: RO pane + READ cap (owner keeps RW).
    let compositor_slot = glass_peer();
    let root_w = tasks()[compositor_slot].cr3;
    let slot_w = crate::shm::share_ro(root_w, crate::cap::table_of(compositor_slot), block)
        .unwrap_or_else(|e| crate::panic_str("P: share_ro: ", e));
    serial::print(format_args!(
        "[P] glass granted: compositor slot {} (READ-only pane of block {})\n",
        slot_w, block
    ));

    // Signal the compositor (it parked in recv).
    match crate::ipc::ipc_send(me, crate::cap::table_of(me), cap_glass, ep_glass, b"R") {
        Ok(()) => {}
        Err(IpcSendError::Block) => crate::task::schedule_from(me),
        Err(IpcSendError::Contract(e)) => crate::panic_str("P: ready send: ", e),
    }

    // --- The wall, direction 3: the screen is invisible to the app ------
    let screen_seen = idt::probe_read(GLASS_SCREEN).is_some();
    if !screen_seen {
        serial::print(format_args!(
            "[P] compositor screen probe denied by MMU (presentation side is W-private)\n"
        ));
    } else {
        serial::print(format_args!("[P] FAIL: app SAW the compositor screen\n"));
    }
    serial::print(format_args!("[P] done\n"));
    crate::task::task_exit(me)
}

/// The glass peer lookup shim (kmain stores the compositor's slot here
/// before spawning; a scenario-wiring detail, not a policy surface).
/// CEP: CEP-2 | Complete (test-wiring)
static mut PEER: usize = 0;

/// The surface block id (painted by P, read by W; scenario wiring).
/// CEP: CEP-2 | Complete (test-wiring)
static mut GLASS_BLOCK: usize = usize::MAX;

/// Record the surface block id (painter side).
/// CEP: CEP-2 | Complete
/// Cost: one store. Fail: cannot fail.
pub fn set_block(id: usize) {
    unsafe { GLASS_BLOCK = id };
}

/// The surface block id (compositor side).
/// CEP: CEP-2 | Complete
/// Cost: one load. Fail: panics if unset (wiring contract).
#[allow(static_mut_refs)]
pub fn glass_block() -> usize {
    let b = unsafe { GLASS_BLOCK };
    if b == usize::MAX {
        crate::panic_str("glass: ", "surface block not wired");
    }
    b
}

/// Record the compositor's task slot (kmain, before the scheduler runs).
/// CEP: CEP-2 | Complete
/// Cost: one store. Fail: cannot fail.
pub fn set_peer(slot: usize) {
    unsafe { PEER = slot };
}

/// The compositor's task slot.
/// CEP: CEP-2 | Complete
/// Cost: one load. Fail: panics if unset (wiring contract).
#[allow(static_mut_refs)]
pub fn glass_peer() -> usize {
    let p = unsafe { PEER };
    if p == 0 {
        crate::panic_str("glass: ", "compositor slot not wired");
    }
    p
}
