# RedOS — Verified Zero-ID, FHE-Native Microkernel OS

RedOS is a capability-based, formally specified microkernel operating system with
**Zero-ID Sovereignty** (no identity mapping, no telemetry, no cloud trust) and
**Tiered Privacy** (AES-256-GCM for general data, FHE reserved for sensitive
compute). The kernel is a *blind* TCB: it routes ciphertext, enforces
capabilities, and never inspects payloads.

Status: **Phase 2 — The RAM-Only Vault & Memory Physics** (see [docs/ROADMAP.md](docs/ROADMAP.md)).

## Core tenets

1. **Zero-ID Sovereignty** — trust is established by local cryptography and
   capabilities, never by identifiers or remote services.
2. **Tiered privacy** — Tier 1: AES-256-GCM everywhere (FS, network, app state).
   Tier 2: FHE (CKKS/BFV) for compute where plaintext must never exist in RAM.
3. **Ephemeral key sovereignty** — master keys live only in mlocked RAM,
   derived (Argon2id, RFC 9106) from a local PIN + hardware salt, wiped
   on power loss. v0.6.0 makes this real: the vault seals the master key
   as an authenticated blob under the PIN-derived KEK (a RAM-only vault
   has no stored verifier — PIN correctness IS the GCM tag), counts
   wrong-PIN attempts in every live state, and destroys itself at budget
   (duress dead-man wipe, terminal `Dead`, all I/O fails closed).
   v0.7.0 removes the last secret constant: the PIN is typed through the
   input service at boot (masked echo; the kernel binary carries no PIN
   — `make secret-audit` proves it), and a compile-time RNG policy can
   refuse to generate a master key from anything but hardware RDRAND
   (terminal `Refused` state).
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
make crypto-test     # build + run the KAT suite (FIPS-197, NIST GCM,
                     # RFC 7693 BLAKE2b, RFC 9106 Argon2id, IEEE 1619 XTS)
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
| v0.2.0  | Zig UEFI bootloader + Rust kernel boots to serial in QEMU          | boot ✓    |
| v0.3.0  | Capability manager + blind IPC + encrypted echo test (Phase 1 MS)  | ipc ✓     |
| v0.4.0  | Isabelle specs (cap algebra, blind IPC), full CI, Phase 1 closure  | proof ✓   |
| v0.5.0  | Memory physics: paging, ephemeral allocator, wipe protocol, zero-copy SHM + MMU-enforced revocation (Phase 2 open) | memphy ✓  |
| v0.6.0  | RAM-only KMS vault: BLAKE2b + Argon2id (RFC 9106 KAT) + XTS-AES-256 (IEEE 1619 KAT), sealed-blob PIN unlock in Locked frames, wrong-PIN dead-man wipe, tick leases, XTS RAM disk | kms ✓     |
| v0.7.0  | Zero-ID identity: MAC'd manifest schema (content-hash bound), sandbox spawner (fresh root + RO code window), default-deny grants, operator prompt handshake, append-only Permission Tracker, input service (no PIN constants), strict-RNG policy; REPAIRS two latent CI failures carried since v0.4/v0.5 (see note) | idnt ✓    |
| v0.8.0  | IPC fast path + Glass Wall (Phase 2 close): GDT/TSS + syscall/sysret ring 3, ELF64 user binaries (W^X loader), blind register rendezvous with direct switch, PCID+INVPCID measured optimization, kernel-text RO from birth (fixes the latent 1-GiB-page low-identity bug), compositor read-only panes (MMU-proven both directions), ring-3 fault containment | fastpath ✓ |

**CI honesty note (v0.7.0).** The ✓ marks above are v0.7.0's local-plus-CI
status. The v0.3.0–v0.6.0 pushes shipped while CI was in fact red — the
proof job died downloading Isabelle (one hanging mirror consumed the job
timeout; now fast-fail bounded per mirror, four mirrors) and the boot job
died on firmware maps larger than the bootloader's 128-entry table (now
coalesced into maximal same-kind regions with a 256-entry contract bound
matching the kernel's handoff validation). Both were invisible locally
(sandbox QEMU emits exactly 123 entries) and surfaced only through the
v0.7.0 review gate — recorded here so the ledger stays honest.

## License & standards

- License: **AGPL-3.0** (inherited from repository origin).
- Code discipline: this repository follows the CEP&CC 0.1 standard in
  [standard.md](standard.md) — see
  [docs/STANDARD-COMPLIANCE.md](docs/STANDARD-COMPLIANCE.md) for the binding
  interpretation for Rust, Zig and C sources.
