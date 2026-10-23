# RedOS — Master Architectural Blueprint (implementation baseline)

This document is the binding architecture for the implementation. It condenses
the approved design (2026-10) and records every decision that changes code.
The coding standard is CEP&CC 0.1 (`standard.md` at repository root).

## Core tenets

1. **Zero-ID Sovereignty** — no real-world identity mapping, no telemetry, no
   "phone home". Trust is established via local cryptography and capabilities,
   not IDs.
2. **Math over Trust (FHE-native, tiered)** — sensitive data is processed as
   ciphertext. The kernel and services route and store data without ever
   decrypting it. Tier 1: AES-256-GCM for general data (fast path).
   Tier 2: FHE (CKKS/BFV) for high-value compute (biometric matching, private
   search) where plaintext must never exist in RAM.
3. **Minimal Verified TCB** — the kernel is strictly mechanism, not policy,
   formally specified in Isabelle/HOL and kept under 15K LOC. Heavy crypto and
   FHE math live in userspace, outside the TCB.
4. **Ephemeral Key Sovereignty** — AES master keys never touch persistent
   storage; they exist only in mlocked RAM and are wiped on power loss or
   reboot (re-authentication required on next boot).

## Layered architecture

### Layer 0 — Boot & Platform Initialization (physical root) — Zig
- **Stage-0 UEFI bootloader** (`bootloader/`): verifies/loads the kernel image,
  parses the ELF, builds identity-mapped page tables, exits boot services,
  jumps to the kernel with a fixed-layout handoff structure (memory map).
  No network boot. TPM measurement hooks are stubs until hardware validation.
- **PAL**: board/chipset init isolated from the generic kernel so board support
  never enters the verified TCB.
- **Entropy source**: harvests hardware noise to seed the KDF (Phase 2).

### Layer 1 — Verified Microkernel (the blind TCB) — Rust (`kernel/`)
- Mechanisms only: threads, virtual memory, IPC, interrupts. No drivers, no
  filesystem, no network stack in the kernel.
- **Capability manager**: unforgeable tokens are the only authority. No root
  user, no global admin. Capability rights: SEND/RECV/GRANT per endpoint.
- **Blind IPC router**: checks message size and destination capability, copies
  payloads without inspection. Payloads are ciphertext by convention.
- **Zero-knowledge scheduler**: cooperative round-robin (Phase 1); per-task
  CR3 address-space roots since v0.5.0 (full TLB flush on switch — the
  revocation-safe baseline; PCID arrives with the fast-path milestone).
- **Memory physics (v0.5.0, real)**:
  - *Ephemeral Page Allocator* (`mm/phys.rs`): every frame carries a class
    (General / Locked / Shared / Reserved). Freeing runs the wipe protocol
    (address-mixed noise, then zero) BEFORE the frame re-enters the pool;
    double frees are named errors. Locked frames (Key Material / FHE State)
    refuse the free path — only the KMS owner may zero them (v0.6.0). The
    anti-swap guarantee is structural: no block-device driver is linked;
    `anti_swap_audit()` verifies the DECLARED external surface
    (audit.rs, reviewed every push) stays free of storage-path names.
  - *Paging* (`mm/pagemap.rs`): 4-level tables, 512 MiB low identity map,
    HHDM at 0xFFFF_8000_0000_0000, per-task windows for zero-copy shared
    memory (PML4[192]) and private pages (PML4[224]). All served frames are
    below the 512 MiB service ceiling and identity-mapped in every root —
    the allocator and table builder never depend on which CR3 is loaded.
  - *IDT + probe protocol* (`mm/idt.rs`): #PF handler with a fixup-based
    safe-probe (read/write). Revocation is enforced by the MMU: a revoked
    mapping produces a #PF, which the handler turns into a named
    "Access Denied" — never a panic, never a silent pass. Unexpected faults
    halt with forensics (CR2/error-code decode).
  - *Zero-copy SHM* (`shm.rs`): transfer demotes the sender's mapping to
    read-only (write-demotion on send), maps the receiver read-write, and
    mints the receiver's capability token — the kernel copies a 24-byte
    descriptor, never the payload. `revoke()` zeroes the CNode slot AND
    tears down the PTEs (with `invlpg` when the affected root is loaded).

### Layer 2 — Userspace runtime & crypto engines — Rust + C
- **Capability-aware libc**: minimal, `no_std`-compatible core (Phase 2).
- **KMS (RAM-only vault)**: Argon2id(PIN + hardware salt) → master AES-256 key
  in mlocked memory; HKDF sub-keys per object; wipe protocol overwrites pages
  before free; keys never hit disk (Phase 2).
- **Homomorphic Compute Engine (HCE)**: background thread pool executing FHE
  circuits (Tier-2 only). C math core (`crypto/`, NTT/polynomial rings) bound
  via FFI from the Rust service (Phase 3). The HCE never holds decryption keys.

### Layer 3 — Core sandboxed services — Rust
Encrypted filesystem (AES-256-GCM, per-file sub-keys), userspace network stack
(default-deny, egress-capability-gated), driver sandboxes (one sandbox per
driver, sensitive inputs routed to HCE/KMS directly), local IPC name service,
time & power services (Phase 2–3).

### Layer 4 — Security, policy & zero-ID identity — Rust
Local declarative policy manifests (no cloud sync), sandbox spawner (init in
strict dependency order), local-only audit log, ZKP generation for external
proofs ("I am over 18" without revealing identity), telemetry blocker that
drops outbound anonymous telemetry attempts (Phase 3–4).

### Layer 5 — Developer tooling & UI — Rust
"Glass Wall" compositor (the only decryption point for display), capability
inspection shell/REPL, capability-based debugger (no ptrace), local P2P package
manager (Phase 4).

## Decision log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| First target arch | x86_64 | Broadest QEMU/hardware support; UEFI boot path |
| Kernel language | Rust (`no_std`, `x86_64-unknown-none`) | Memory safety in the TCB, FFI into C cores |
| Bootloader language | Zig 0.13 | Composable freestanding code, small stage-0 |
| Crypto/FHE core | C11 freestanding | Auditable hot math, later SIMD/CLMUL tuning |
| IPC payload policy | Kernel never inspects | Blind routing is a spec-level property |
| Phase-1 crypto | AES-256-GCM (C core, NIST-vector-tested) | Tier-1 path; FHE arrives in Phase 3 |
| Formal specs | Isabelle/HOL, real on day 1 | Capability algebra + IPC abstraction; v0.4.0 sessions build `sorry`-free (ledger: proof/TODO.md) |
| Phase-2 paging baseline | No PCID, full TLB flush per CR3 load | A stale TLB entry can never outlive a revocation; the fast-path milestone adds ASIDs as a measured optimization |
| Frame addressing | Identity (≤ 512 MiB service ceiling) for allocator + table builder | Works under any active CR3 — the HHDM does not exist until the kernel switches (v0.5.0 bring-up lesson) |
| IDTR layout | `repr(C, packed(1))` — limit@0, base@2 | The hardware IDTR is packed; a padded struct loads garbage (v0.5.0 bring-up lesson, caught by the sidt readback assertion) |
| PTE coherence | `invlpg` after flag-change/unmap on the CURRENT root | Without it the CPU serves stale RW/live translations (v0.5.0 bring-up lesson) |
| Git protocol | main + annotated tags at each 25% milestone | Reviewable quarterly pushes; scope widened by user directive (no LOC ceiling) |

## LOC ledger (targets from the approved blueprint)

| Component | Target LOC | Phase |
|-----------|------------|-------|
| Verified TCB (kernel) | 8,000–12,000 | 1–2 |
| Isabelle proofs & specs | 50,000–100,000 | 1–4 |
| Bootloader + PAL | 3,000–6,000 | 1 |
| Userspace libc / runtime | 15,000–25,000 | 2 |
| Core services (FS, net, …) | 40,000–70,000 | 2–3 |
| KMS (RAM-only vault) | 5,000–10,000 | 2 |
| FHE engine (HCE, C core + FFI) | 20,000–40,000 | 3 |
| Dev tools, UI, shell | 15,000–30,000 | 4 |
| Security / policy / init | 5,000–10,000 | 3–4 |
| Build / CI / test infra | 10,000–20,000 | 1–4 |
| **Total (shippable)** | **~170,000–220,000** | — |

Live counts: run `make loc`.
