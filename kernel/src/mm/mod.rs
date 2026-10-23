//! RedOS kernel — memory management (Phase 2: "the physics of privacy").
//!
//! This module tree implements Pillar 2 of the redOS design:
//!
//! * [`phys`]    — the Ephemeral Page Allocator. Pages are classified
//!                 (General / Locked / Shared); locked pages are
//!                 architecturally forbidden from ever reaching storage
//!                 (anti-swap) and every freed frame is overwritten with
//!                 noise before it can be handed out again (wipe protocol).
//! * [`pagemap`] — 4-level x86_64 paging with a higher-half direct map and
//!                 one page-table root per task (the basis of zero-copy
//!                 shared memory and hardware-level revocation).
//! * [`idt`]     — the Interrupt Descriptor Table with the page-fault
//!                 handler and the safe-probe protocol. Revocation is
//!                 enforced by the MMU: an access to an unmapped capability
//!                 becomes a hardware trap, not a policy check.
//!
//! Phase-2 scope notes (documented decisions, not oversights):
//!
//! * Ring 0 only. Tasks are kernel threads with private address-space
//!   *roots* (CR3 per task); the user/supervisor split and per-ring
//!   isolation arrive with the ring-3 IPC fast-path milestone. The
//!   revocation guarantee demonstrated in Phase 2 is MMU-enforced (a
//!   revoked mapping faults), which does not depend on ring separation.
//! * No PCID/invpcid yet: every CR3 load fully flushes the TLB. This is
//!   the *safe* baseline (a stale TLB entry can never outlive a
//!   revocation); the fast-path milestone adds address-space identifiers
//!   as a measured optimization.
//! * No swap exists in any form: the kernel links no block-device driver
//!   and the allocator structurally cannot write a frame anywhere but
//!   RAM. The anti-swap guarantee is therefore a compile-time property,
//!   re-asserted by `phys::anti_swap_audit()`.
//!
//! CEP: CEP-1 | Complete (Phase 2 scope)
//! Assumes: x86_64 long mode; UEFI handoff (see handoff.rs); interrupts
//!          disabled; one CPU.

pub mod idt;
pub mod pagemap;
pub mod phys;
