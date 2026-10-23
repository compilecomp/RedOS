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

## Next proof targets (Phase 2+)

- Task state machine: no Dead-but-resumable, no Runnable-with-stale-context.
- Scheduler liveness under cooperative semantics.
- KMS state machine: duress counter, destroyed-vault fail-closed (with the
  v0.6.0 KMS — extends `Mem.thy`'s Locked-class theorems).
- XTS sector encryption: tweak independence (with the v0.6.0 RAM disk).
- Manifest spawner: hash-mismatch refusal is monotone (with v0.7.0).
