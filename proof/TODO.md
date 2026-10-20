# Isabelle/HOL proof session — TODO ledger (CEP&CC Law 8)

Policy: every `sorry` in `proof/` must be listed here with its cost and
closure milestone. A `sorry` that is not in this ledger is a CI failure in
spirit; the ledger is reviewed at every quarterly push.

## Current ledger

| # | Location | Statement | Closure milestone |
|---|----------|-----------|-------------------|
| — | — | none — v0.4.0 sessions build without `sorry` | — |

## Accepted model simplifications (not sorries — documented abstractions)

1. `IPC.thy` models waiters as booleans (Phase 1 enforces at most one
   blocked task per side via named contract errors). Multi-waiter queues
   (Phase 2 scheduler) will generalize these to task sets.
2. `IPC.thy` models the kernel copy as the identity on the message value:
   the kernel-side `copy_nonoverlapping` cannot change content, only
   location. A hardware DMA model (Phase 3 FHE path) will need a real
   memory model.
3. `Cap.thy` uses `right set` instead of the kernel's two-bit mask; the map
   between representations is the identity on {Send, Recv}.

## Next proof targets (Phase 2+)

- Task state machine: no Dead-but-resumable, no Runnable-with-stale-context.
- Scheduler liveness under cooperative semantics.
- KMS wipe protocol: zeroization before free (with the Phase 2 KMS).
