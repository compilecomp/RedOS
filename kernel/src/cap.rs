//! RedOS kernel — capability manager.
//!
//! The heart of the security model: authority is carried exclusively by
//! unforgeable capability slots. There is no root, no admin, no global
//! namespace. A task can only name a resource through a capability that was
//! explicitly minted into its table; the kernel validates rights on every
//! use. This module is the Rust twin of `proof/Cap.thy` (capability algebra:
//! rights are a lattice, minting only narrows, revocation only removes).
//!
//! CEP: CEP-1 | Complete (Phase 1: endpoint capabilities)
//! Cost: mint O(1), lookup O(1) (direct slot index), revoke O(1).
//! Fail: every use validates rights and liveness; violations panic
//!       (fail-fast). Policy-based degradation is Phase 2+ (audit log).
//! Assumes: single kernel thread mutates tables (Phase 1 cooperative);
//!          MAX_CAPS=16 per task, static tables (no heap).

/// Capability rights (monotone lattice: subset ordering; GRANT implies
/// the right being granted may be transferred only if held).
pub mod rights {
    #[allow(dead_code)] // lattice zero element; named for the algebra (Cap.thy)
    pub const NONE: u8 = 0;
    pub const SEND: u8 = 1;
    pub const RECV: u8 = 2;
    /// SEND | RECV — convenience for bidirectional endpoints.
    pub const RW: u8 = SEND | RECV;
}

pub use rights::{RECV, RW, SEND};

pub const MAX_CAPS: usize = 16;

/// What a capability slot names. Phase 1: endpoints only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CapKind {
    Free,
    Endpoint {
        /// Index into the static endpoint table (kernel object reference).
        ep: usize,
        /// rights::SEND / rights::RECV bitmask.
        rights: u8,
    },
}

/// One slot of a capability table.
#[derive(Clone, Copy)]
pub struct CapSlot {
    pub kind: CapKind,
}

const fn free_slot() -> CapSlot {
    CapSlot {
        kind: CapKind::Free,
    }
}

/// Per-task capability table (CNode).
pub struct CTable {
    pub slots: [CapSlot; MAX_CAPS],
}

impl CTable {
    pub const fn new() -> Self {
        CTable {
            slots: [free_slot(); MAX_CAPS],
        }
    }

    /// CEP: CEP-1 | Complete
    /// Cost: O(1) scan for a free slot (bounded MAX_CAPS).
    /// Fail: Err("table full") — authority exhaustion is a named condition,
    ///       never a silent overwrite.
    pub fn mint(&mut self, ep: usize, rights: u8) -> Result<usize, &'static str> {
        // Lattice check: only SEND/RECV composites are mintable (minting
        // only narrows — Cap.thy). Bounded endpoint index (Law 2).
        if rights & !(SEND | RECV) != 0 || rights == 0 {
            return Err("rights outside the SEND/RECV lattice");
        }
        if ep >= super::ipc::MAX_ENDPOINTS {
            return Err("endpoint index out of range");
        }
        let free = self
            .slots
            .iter()
            .position(|s| matches!(s.kind, CapKind::Free))
            .ok_or("capability table full")?;
        self.slots[free].kind = CapKind::Endpoint { ep, rights };
        Ok(free)
    }

    /// CEP: CEP-1 | Complete
    /// Cost: O(1).
    /// Fail: Err if the slot is free or the endpoint index mismatches —
    ///       a dangling or forged reference cannot pass lookup.
    pub fn lookup_endpoint(&self, slot: usize, ep: usize) -> Result<u8, &'static str> {
        match self.slots[slot].kind {
            CapKind::Endpoint { ep: e, rights } if e == ep => Ok(rights),
            _ => Err("capability does not name this endpoint"),
        }
    }

    /// CEP: CEP-1 | Complete
    /// Cost: O(1). Revocation is monotone: rights only shrink.
    /// Fail: cannot fail (revoking a free slot is a no-op by design).
    /// Phase 2 callers: audit-log + policy engine exercise revoke.
    #[allow(dead_code)]
    pub fn revoke(&mut self, slot: usize) {
        self.slots[slot].kind = CapKind::Free;
    }
}
