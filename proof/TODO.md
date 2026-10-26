# Isabelle/HOL proof session — TODO ledger (CEP&CC Law 8)

Policy: every `sorry` in `proof/` must be listed here with its cost and
closure milestone. A `sorry` that is not in this ledger is a CI failure in
spirit; the ledger is reviewed at every quarterly push.

## Current ledger

| # | Location | Statement | Closure milestone |
|---|----------|-----------|-------------------|
| — | — | none — v0.5.0 sessions build without `sorry` | — |

## Accepted model simplifications (not sorries — documented abstractions)

1. `IPC.thy` models waiters as booleans (Phase 1 enforces at most one
   blocked task per side via named contract errors). Multi-waiter queues
   (the fast-path milestone) will generalize these to task sets.
2. `IPC.thy` models the kernel copy as the identity on the message value:
   the kernel-side `copy_nonoverlapping` cannot change content, only
   location. A hardware DMA model (Phase 3 FHE path) will need a real
   memory model.
3. `Cap.thy` uses `right set` instead of the kernel's two-bit mask; the map
   between representations is the identity on {Send, Recv}. The v0.5.0
   shared-memory rights (READ/WRITE) are modeled in `Revoke.thy`'s `perm`
   type rather than extending `Cap.thy`'s endpoint lattice — the two
   resource kinds have disjoint capability constructors in the kernel
   (`CapKind::Endpoint` vs `CapKind::Shm`), so separate types are faithful,
   not a shortcut.
4. `Mem.thy` models the allocator as a total function over a closed command
   type (`AAlloc`/`AFree`); guard refusals leave state unchanged, which
   abstracts the kernel's named errors. The anti-swap theorem is a
   closed-world I/O statement (`io_of` total over the command type); the
   kernel-level completeness argument is the linked-symbol audit
   (`phys::anti_swap_audit`) — together they are the guarantee.
5. `Mem.thy`'s wipe theorem is the STRUCTURAL half (a granted frame was
   wiped). The CONTENT half (noise unrelated to the old pattern) is
   enforced empirically by the boot test's 256-window sweep; the xorshift
   noise source upgrades to an AES-CTR keystream with the v0.6.0 KMS.
6. `Revoke.thy` models revocation monotonicity with a monotone `sdead`
   registry — the faithful twin of the kernel's `revoked` flag (set by
   `shm.rs::revoke`, checked by `map_for`/`transfer`: no kernel path maps
   a revoked block again). The kill switch's mapping teardown is modeled
   as `unmap_all` (every window of the revoked block), matching
   `shm.rs::revoke` which unmaps all pages of the block.
7. `Revoke.thy` models the zero-copy transfer as ONE atomic record update
   (`s_transfer` installs capability + mapping together). The kernel
   performs demote → mint → map → commit in sequence — unobservable as
   intermediate states, because the cooperative single-task model gives
   no other task (and no interrupt) a scheduling point mid-transfer, and
   a post-mint failure rolls the mint back (no mapping ever exists
   without its capability). A preemptive kernel (fast-path milestone)
   will need either an atomic commit object or a formal two-phase model.
8. `Revoke.thy` does not model task IDs as flows of execution (no
   scheduler): `CAcc` events stand for whatever the running task does, and
   admission is purely the MMU predicate. Ring-3 user/supervisor split
   (fast-path milestone) will extend the model with an execution mode.
9. `Kms.thy` models PIN correctness as an abstract boolean command
   (`KUnlock pin`). The cryptographic half — that only the Argon2id KEK
   of the true PIN verifies the sealed blob's GCM tag — is pinned by the
   RFC 9106 KAT in tests/crypto (Law 3 division of labor: the theorem
   owns the state machine, the KAT owns the crypto).
10. `Kms.thy` lease expiry is lazy and tick-based (ticks = context
   switches, monotone). Wall-clock leases (timer interrupts) would need
   the fast-path milestone's interrupt model first; monotone ticks are
   the conservative approximation (expiry can only come earlier).
11. `Kms.thy` does not model the Argon2id arena's CONTENT (password-
   derived intermediate blocks): the arena's wipe-after-attempt is
   enforced by the kernel (`scrub_arena`) and covered by `Mem.thy`'s
   locked-forever + wipe-before-reuse theorems for the frames it spans.
12. `Kms.thy` treats VWiping as a guard state only (the duress wipe is
   atomic in the model). In the kernel the wipe is a sequence, but the
   cooperative single-CPU model gives no observer a scheduling point
   inside it (same argument as item 7).
13. `Kms.thy` divergences from kms.rs recorded for honesty (all benign,
   none load-bearing): (a) the duress branch does not bump `vatt` — the
   kernel increments ATTEMPTS to MAX before wiping, so `attempts_used()`
   reads 3 after duress where the model freezes at 2; (b) `ok v
   (KUnlock _)` means "attempt serviced", not "vault opened" — the
   theorems about outcomes use the state-machine consequences instead;
   (c) lease use does not distinguish NoSuchLease from Expired (both
   refuse; the kernel's named errors are finer-grained than the model).
14. `Ident.thy` models the manifest MAC and the binary content hash as
   abstract values (`mmac_ok :: bool`, `mhash/phash :: nat`): the
   concrete bindings are keyed-BLAKE2b under a vault-derived key and
   BLAKE2b-256 over the entry image — both pinned by KATs (RFC 7693
   host suite) and exercised empirically by the QEMU spawn refusals
   (MAC-REFUSED / HASH-REFUSED banners). A cryptographic model of
   BLAKE2b is out of scope for the TCB model.
15. `Ident.thy` takes the operator's prompt decision as a command
   parameter (`ILeaseReq ... bool` / `IDiskReq ... bool`): the prompt
   handshake is the human half, outside the TCB by design. The model
   proves what the KERNEL enforces around that decision (policy caps
   are mechanical, denials never grant, every decision is recorded).
   The kernel's three denial sub-reasons (policy cap / forged request /
   KMS error) merge into one DDenied outcome — same observable effect
   (record + no cap), finer-grained notes live in the kernel's ledger.
16. `Ident.thy` does not model task-slot non-reuse: the kernel never
   recycles Dead slots (`task::spawn` scans Free only, `spawn_at`
   ditto), so a respawned index is impossible in the implementation.
   The model's ISpawn guard is only `¬ ialive s t`; a post-exit respawn
   of the same index would start a fresh authority lifetime with its
   own records (the tracked invariant still holds). Structural closure
   (an `ever_spawned` registry) is deferred to the ring-3 identity
   milestone, where task identity becomes structural anyway.
18. `Ident.thy` proves the one-directional tracker invariant (a live
   authority implies a Granted record exists); the kernel's
   `has_authority` is stronger: LATEST record wins (a later
   Denied/Revoked/Expired supersedes an earlier Granted). The kernel is
   the more conservative of the two and the model's theorems are all
   one-directional, so nothing overclaims — but the liveness semantics
   (latest-wins) is enforced only in the implementation. If a milestone
   ever needs the kernel's exact liveness (e.g. to prove a denial
   cannot resurrect authority), extend the model with the
   latest-decision function and prove it there.
17. `Kms.thy` models the seal step as pre-history (the vault starts in
   VSealed or VRefused); init's Argon2id seal and the entropy-policy
   gate are covered by the rng_admits theorems + the KAT suite, not by
   a KSeal command. A model of init would need the Argon2id arena in
   the vault record — deferred until a milestone touches it.

## Next proof targets (Phase 2+)

- Task state machine: no Dead-but-resumable, no Runnable-with-stale-context.
- Scheduler liveness under cooperative semantics.
- KMS state machine: DONE at v0.6.0 (`Kms.thy`: duress counter,
  destroyed-vault fail-closed, lease lazy expiry, unlock outcomes).
- XTS sector encryption: tweak independence (with the v0.7.0 storage
  hardening; the IEEE 1619 KAT pins the crypto half meanwhile).
- Manifest spawner: DONE at v0.7.0 (`Ident.thy`: refusal inertness,
  default-grant atomicity, no-cap-without-record preservation, TTL
  policy cap, operator-denial neutrality, expiry/exit clearance).
- Runtime request protocol: multi-task concurrent request queues (the
  one-sandbox model covers v0.7.0's single sandbox slot).
