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

## Phase 2 — The RAM-Only Vault & Memory Physics (current cycle; scope widened: no LOC ceiling)

The user directive for this cycle: **no hard LOC limit — build the full
redOS.** The quarterly cadence and the independent-review gate are unchanged;
only the scope ceiling is lifted.

| Push | Tag | Scope | Exit criteria |
|------|-----|-------|---------------|
| 25% | v0.5.0 | **Memory physics** (Pillar 2): 4-level paging + HHDM, per-task CR3 roots, Ephemeral Page Allocator (classification, wipe protocol, mlock mandate, anti-swap audit), IDT + #PF probe protocol, zero-copy shared memory with CNode kill switch (write-demotion on transfer, MMU-enforced revocation) | Six MEMPHY banners in QEMU: isolation, wipe, lock, zero-copy, revoke, complete; `Mem.thy` + `Revoke.thy` sorry-free |
| 50% | v0.6.0 | **RAM-only KMS vault** (Pillar 2): Argon2id (RFC 9106, C core + KAT vectors), PIN → master key into Locked-class frames, XTS-encrypted RAM disk, lease expiry, duress counter / dead-man's wipe | KMS KATs pass; encrypted RAM-disk round-trip in QEMU; wrong-PIN counter destroys the vault (fail-closed) — **DELIVERED** |
| 75% | v0.7.0 | **Zero-ID identity** (Pillar 1): manifest schema (binary hash, sandbox profile, requested capabilities, lease terms), sandbox spawner, default grants, runtime prompt handshake | Spawner refuses hash mismatch; prompt grants session/lease-scoped caps, tracked by the Permission Tracker — **DELIVERED** |
| 100% | v0.8.0 | **IPC fast-path + Glass Wall** (Pillar 2/5): `syscall`/`sysret` ring transition, rendezvous register path, PCID/invpcid measured optimization, compositor read-only pixel buffers | Fast-path IPC under 100-cycle budget with disassembly evidence; compositor cannot read app memory (MMU-proven) |

**v0.5.0 delivered (this push).** Kernel-side memory physics is real:
the allocator classifies every frame (General/Locked/Shared/Reserved),
freeing runs the wipe protocol before reuse, locked frames refuse the
free path, and revocation is enforced by the MMU — a revoked capability
produces a page fault, caught by the probe protocol and surfaced as a
named denial. Bring-up lessons are recorded in the decision log
(packed IDTR layout, identity addressing for pre-switch table setup,
invlpg on current-root PTE changes).

Formal specs added at v0.5.0: `proof/Mem.thy` (wipe-before-reuse,
locked-never-reused, anti-swap closed-world I/O) and `proof/Revoke.thy`
(revocation soundness: after the kill switch, no admitted access ever
again; transfer pairing). Zero `sorry`.

**v0.6.0 delivered (this push).** The RAM-only KMS vault is real:

* **C core, RFC-grade.** BLAKE2b (RFC 7693, incremental + one-shot,
  7 pinned reference digests), Argon2id (RFC 9106, section 5.3 official
  vector verbatim, freestanding, caller-provided work area), and
  XTS-AES-256 (IEEE 1619-2007 Annex B 512-byte data-unit vector; NIST
  SP 800-38E subset — partial data units get a named error, never
  improvised ciphertext stealing). AES-256 gained the FIPS-197 inverse
  cipher for XTS. 92 test assertions (60 check sites) + link-level
  freestanding check.
* **Kernel vault (kms.rs).** Master key generated at boot (RDRAND with
  CPUID guard; documented weak TSC fallback for QEMU's default CPU),
  sealed immediately as `GCM(master)` under `Argon2id(PIN, salt)` — a
  RAM-only vault has no stored verifier, so PIN correctness is proven
  by the GCM tag, not by comparing against anything persistent. Master,
  blob, and the 8 MiB Argon2id arena are all Locked-class frames (the
  v0.5.0 mlock mandate makes them unfreeable by construction). Wrong-PIN
  attempts are counted FIRST in every live state (hammering an open
  vault counts too); the budget-satisfying attempt fires the duress
  dead-man wipe — master, blob, arena, leases zeroized, wipe-key
  upgrade reverted, terminal `Dead` state — before any crypto runs.
* **Leases.** Derived keys (keyed BLAKE2b, domain-separated) with
  scheduler-tick TTLs and lazy expiry: first use past expiry wipes the
  key and refuses forever. Ticks are context switches — the only clock
  in a no-interrupt kernel, and the conservative approximation
  (expiry can only come earlier).
* **XTS RAM disk (ramdisk.rs).** 16 x 512 B sectors in General frames;
  the disk key is derived fresh per operation and zeroized after use —
  key material never rests outside the vault. Encryption at rest is
  asserted in QEMU (raw sector bytes != plaintext). All I/O fails
  closed (`VaultDead`) once duress fires.
* **Allocator wipe upgrade.** The v0.5.0 xorshift wipe stream upgrades
  to AES-256-CTR keyed from the vault at unlock (SP 800-38A, per-frame
  nonces from physical addresses), reverting to keyless xorshift at
  duress — the wipe never outlives the key that justifies it.
* **Bring-up lessons (decision log).** (1) With 3+ tasks, a yielding
  task's scheduler scan can wrap to kmain's abandoned slot 0 — kmain is
  now marked non-Runnable at boot; (2) a yield that must always return
  (lease expiry clock) needs the self-switching `yield_tick`, not
  `schedule_from` (which halts when the caller is the only runnable
  task); (3) the wrong-PIN budget must be checked in EVERY live state —
  an AlreadyUnlocked guard before the counter would let hammering an
  open vault run forever.

Formal specs added at v0.6.0: `proof/Kms.thy` (attempt-counter
monotonicity across successes, duress destroys + Dead terminality via
the `dead_inv` invariant, lease lazy expiry + no-serve-without-regrant,
fail-closed outcomes outside Unlocked, unlock outcome theorems). Zero
`sorry`; model simplifications recorded in `proof/TODO.md` (items 9-12).

**v0.7.0 delivered (this push).** Zero-ID identity is real — authority
flows from content and operator decisions, never from identifiers:

* **No secret constants.** The vault PIN is typed through the input
  service (polled UART RX, masked echo) at seal AND at unlock; the
  kernel binary carries no PIN (`make secret-audit` greps the image and
  fails if the operator PIN string ever reappears). The wrong-PIN
  vector stays a public test input. The entropy policy switch
  (`RngPolicy`, compile-time) admits only RDRAND under Strict: a
  machine without hardware entropy enters the terminal `Refused` state
  instead of pretending (`Kms.thy`: refused_terminal,
  ev_never_enters_refused — no command enters it; init-only).
* **Manifests (64 bytes, MAC'd).** magic/version/profile/requested
  authorities/lease-TTL/binary content hash + keyed-BLAKE2b MAC under a
  vault-derived key (`redos/manifest/v1` domain separation). The vault
  being open IS the trust anchor: no PKI, no IDs, and a sealed/dead
  vault refuses every spawn (fail-closed, proven inert in `Ident.thy`).
* **Sandbox spawner.** Refusal order: MAC first, then the content hash
  (BLAKE2b-256 over the entry image — the Phase-2 program model is
  in-kernel functions; ELF user binaries arrive with ring 3 in
  v0.8.0), then profile validity. Admitted spawns get a fresh
  address-space root, the code window mapped READ-ONLY at a private
  window (the spawn-granted W^X surface — image-wide text RO is a
  v0.8.0 paging item, documented), and exactly one default grant:
  SEND/RECV on the prompt endpoint. Default-deny beyond that.
* **Operator prompt handshake.** Requests flow over the prompt
  endpoint as fixed 32-byte records; the identity service applies the
  mechanical TTL policy cap FIRST (STRICT profile: no prompt can
  exceed the cap — math over trust), then asks the operator over the
  serial console (any answer but y/Y denies — fail-closed default).
  Session-scoped grants die with the task; lease-scoped grants are
  owner-bound KMS leases with tick TTLs (theft refuses with
  NoSuchLease — indistinguishable from absence).
* **Permission Tracker.** An append-only ledger: every grant, denial,
  expiry and revocation is recorded BEFORE the corresponding
  capability exists (`Ident.thy`: no-cap-without-record preservation
  across every command and every sequence). Disk I/O consults the
  tracker at use time (ramdisk NotGranted); task_exit records Revoked
  and clears the table (session death is mechanical, not conventional).
* **Bring-up lessons (decision log).** (1) `create_endpoint` now
  RESERVES its slot — the emptiness test let three creates collide on
  index 0, silently merging every endpoint's traffic; (2) `yield_tick`
  is now fair (scan from cur+1, self-switch only as the last resort) —
  the old scan-from-cur always re-picked the yielding task and starved
  every task woken while it kept yielding; (3) a woken receiver must
  consume the `delivered` flag before re-entering recv (the v0.3.0
  lesson, relearned by the vault client's completion wait).

Formal specs added at v0.7.0: `proof/Ident.thy` (manifest spawner:
refusal inertness, admission atomicity, tracked-capability invariant,
TTL policy cap, operator-denial neutrality, expiry + exit clearance)
and `proof/Kms.thy` extensions (entropy policy decision table, the
terminal Refused state with its own reachability invariant). Zero
`sorry`; model simplifications recorded in `proof/TODO.md` (items
14-18).

**CI repairs (review-gate finds, v0.7.0 closes).** The independent
review surfaced two latent failures the local sandbox could never see:
(1) the CI proof job had not RUN since v0.4.0 — a hanging Isabelle
mirror consumed the job's whole timeout (downloads are now hard-bounded
per mirror across four mirrors), and the reviewer's hand-proof audit
found a real latent bug the dead job had been hiding
(`wrong_pin_stays_sealed` needed the `key_inv` reachability premise —
fixed); (2) the CI boot job failed on firmware memory maps larger than
the bootloader's 128-entry table (local QEMU emits exactly 123) — the
bootloader now coalesces the map into maximal same-kind regions under a
256-entry contract bound that matches the kernel's handoff validation.
The README ledger records the red history.

## Phase 3 — The Selective FHE Engine (next cycle)

HCE service with background thread pool; C NTT/polynomial core behind FFI;
integration with KMS; the FHE Algorithmic Router (TFHE for boolean/control
flow, BFV for exact integers, CKKS for approximate reals — data-typing,
depth budgeting, thermal gating, arena pinning). Milestone: private search
over an encrypted dataset via background FHE threads without blocking the
main thread.

## Phase 4 — The Sovereign Network & Decentralized Fabric

Dark Local Mesh (chameleon MACs, hashed overlay IPs, blind beacons, OOB
trust handshake, local onion routing, capability-gated relaying) and the
Decentralized Update Fabric (content-hash addressing over DHT/mirrors,
Ed25519-signed manifests, reproducible-build verification, A/B atomic
snapshot swap with instant rollback). Boot hardening lands here as well:
Stage-1 kernel signature verification, duress PIN, dead-man's switch tied
to the KMS, first-boot supply-chain audit.

## Phase 5 — v1.0 Polish

Full Isabelle proof discharge of the accumulated ledgers, Sovereignty
Dashboard console, capability shell/REPL, final independent audit across
all components.

## Formal verification plan

- `proof/Cap.thy` — capability algebra: rights, monotonicity, no-forgery.
- `proof/IPC.thy` — blind routing abstraction: router output independent of
  payload content; size+capability checks only.
- `proof/Invariants.thy` — kernel invariants over capability tables and
  endpoint states.
- `sorry` ledger lives in `proof/TODO.md`; each entry has a closure phase.
