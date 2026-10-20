# RedOS — Verified Zero-ID, FHE-Native Microkernel OS

RedOS is a capability-based, formally specified microkernel operating system with
**Zero-ID Sovereignty** (no identity mapping, no telemetry, no cloud trust) and
**Tiered Privacy** (AES-256-GCM for general data, FHE reserved for sensitive
compute). The kernel is a *blind* TCB: it routes ciphertext, enforces
capabilities, and never inspects payloads.

Status: **Phase 1 — The Blind Core** (see [docs/ROADMAP.md](docs/ROADMAP.md)).

## Core tenets

1. **Zero-ID Sovereignty** — trust is established by local cryptography and
   capabilities, never by identifiers or remote services.
2. **Tiered privacy** — Tier 1: AES-256-GCM everywhere (FS, network, app state).
   Tier 2: FHE (CKKS/BFV) for compute where plaintext must never exist in RAM.
3. **Ephemeral key sovereignty** — master keys live only in mlocked RAM,
   derived (Argon2id + HKDF) from a local PIN/biometric + hardware salt, wiped
   on power loss.
4. **Minimal verified TCB** — the kernel is mechanism-only, target 8,000–12,000 LOC
   (hard cap 15,000), with Isabelle/HOL specifications in `proof/`.

## Layout

| Path          | Language | Layer                                          |
|---------------|----------|------------------------------------------------|
| `bootloader/` | Zig      | L0 — Stage-0 UEFI boot, platform init          |
| `kernel/`     | Rust     | L1 — verified microkernel (caps, IPC, threads) |
| `crypto/`     | C        | crypto cores (AES-256-GCM now; FHE math later) |
| `proof/`      | Isabelle | formal specifications of the TCB               |
| `docs/`       | md       | architecture, roadmap, standard compliance     |

## Build (host, no root required)

```sh
make crypto-test     # build + run NIST GCM vectors (host)
make freestanding-check  # compile crypto core freestanding (kernel-grade flags)
make loc             # LOC ledger per component
```

Toolchains: any C11 compiler for the crypto core; Rust stable
(`x86_64-unknown-none`) for the kernel; Zig 0.13 for the bootloader;
QEMU + OVMF + mtools for boot tests (added with the v0.2.0 milestone).

## Milestone ledger

| Tag     | Scope                                                              | CI status |
|---------|--------------------------------------------------------------------|------------|
| v0.1.0  | Monorepo scaffold, AES-256-GCM core (C) + NIST vectors, docs, CI   | crypto ✓  |
| v0.2.0  | Zig UEFI bootloader + Rust kernel boots to serial in QEMU          | planned   |
| v0.3.0  | Capability manager + blind IPC + encrypted echo test (Phase 1 MS)  | planned   |
| v0.4.0  | Isabelle specs (cap algebra, blind IPC), full CI, Phase 1 closure  | planned   |

## License & standards

- License: **AGPL-3.0** (inherited from repository origin).
- Code discipline: this repository follows the CEP&CC 0.1 standard in
  [standard.md](standard.md) — see
  [docs/STANDARD-COMPLIANCE.md](docs/STANDARD-COMPLIANCE.md) for the binding
  interpretation for Rust, Zig and C sources.
