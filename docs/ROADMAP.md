# RedOS Roadmap & Push Protocol

## Quarterly push protocol (session contract)

Work is pushed to `main` in four verified increments per session cycle. A
push is only issued after: (a) all local tests pass, (b) an independent agent
code review has been performed and blocking findings fixed, (c) the worklog is
updated. Each push is an annotated tag `v0.<n>.0`.

## Phase 1 — The Blind Core (this cycle)

| Push | Tag | Scope | Exit criteria |
|------|-----|-------|---------------|
| 25% | v0.1.0 | Monorepo scaffold, docs, CI base, C AES-256-GCM core | NIST TC13–16 pass (host), freestanding compile clean |
| 50% | v0.2.0 | Zig UEFI bootloader, Rust `no_std` kernel skeleton | Kernel prints serial banner through OVMF+QEMU |
| 75% | v0.3.0 | Capability manager, blind IPC router, two threads | Encrypted echo: A encrypts → blind kernel routes → B decrypts, in QEMU |
| 100% | v0.4.0 | Isabelle specs (capability algebra, IPC abstraction, invariants), full CI | `isabelle build` green in CI; QEMU test green; Phase 1 milestone closed |

**Phase 1 CLOSED at v0.4.0.** Formal specs: `proof/Cap.thy` (rights lattice,
mint monotonicity, no-forgery reachability, revocation monotonicity) and
`proof/IPC.thy` (payload-independence / blindness theorem, endpoint state
invariants, revoked-capability stutter). Zero `sorry` — see
`proof/TODO.md` for the accepted model simplifications.

**Phase 1 milestone (blueprint):** "Hello World" where Thread A encrypts a
message, the kernel routes it blindly, and Thread B decrypts it.

## Phase 2 — The RAM-Only Vault & AES runtime (next cycle)

Userspace boots; KMS derives keys from PIN (Argon2id + HKDF) into mlocked
pages; encrypted RAM-disk FS uses per-file sub-keys. Milestone: boot, enter
PIN, create file, reboot, enter PIN, read file; keys never touch disk.

Hardening items carried into Phase 2 (explicit, from v0.1.0 review):
- AES S-box cache-timing hardening (bitsliced or CLMUL path), re-class CEP-0
  with disassembly + benchmark evidence.
- Secret-zeroization review: verify wipe stores are not elided (linker/
  compiler-level analysis), upgrade to a verified wipe primitive.

## Phase 3 — The Selective FHE Engine

HCE service with background thread pool; C NTT/polynomial core behind FFI;
integration with KMS. Milestone: private search over an encrypted dataset via
background FHE threads without blocking the main thread.

## Phase 4 — The Glass Wall & Polish

Compositor, capability shell, ZKP local auth, full Isabelle proof discharge.
Milestone: v1.0 release — a verified, zero-ID, tiered-privacy OS.

## Formal verification plan

- `proof/Cap.thy` — capability algebra: rights, monotonicity, no-forgery.
- `proof/IPC.thy` — blind routing abstraction: router output independent of
  payload content; size+capability checks only.
- `proof/Invariants.thy` — kernel invariants over capability tables and
  endpoint states.
- `sorry` ledger lives in `proof/TODO.md`; each entry has a closure phase.
