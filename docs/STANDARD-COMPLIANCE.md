# CEP&CC 0.1 — Binding Interpretation for RedOS (Rust / Zig / C)

`standard.md` (CEP&CC 0.1, "Psychopathic Tier") is normative for this
repository. It is written with C++26 as target dialect; this document defines
how its laws bind the languages RedOS actually uses. Where the standard is
stricter than this interpretation, the standard wins.

## The eight laws, operationalized

| Law | Enforcement in RedOS |
|-----|----------------------|
| 1 — No hidden cost | No heap allocation, virtual dispatch, or formatting in CEP-0/CEP-1 paths without a CEP header declaring it. Rust: no `alloc` in kernel without documented allocator; no `dyn` in hot paths. C: no hidden libc calls (freestanding build enforces). Zig: no hidden allocator parameters. |
| 2 — No silent assumptions | Every assumption (alignment, endianness, width, ABI, input validity, lifetime, reentrancy, interrupt safety) is written in the CEP header *and* checked by code (assertion, type constraint, or test). |
| 3 — No comment-only invariants | Every invariant has at least one of: `static_assert`/`comptime` check, debug assertion, runtime check, CI test, or Isabelle proof. The NIST-vector tests are the enforcement for the crypto core. |
| 4 — No unmeasured hot code | Hot functions (CEP-0) ship with disassembly + benchmark evidence under `docs/measurements/` before their milestone closes. Phase 1 has no CEP-0 code; AES/GCM is CEP-1 until measured. |
| 5 — No unreadable hot code | Review checklist: control flow, memory pattern, and failure behavior must be auditable without guessing. |
| 6 — No unbounded failure | Every function declares its failure modes and returns explicit status (`red_crypto_rc`, Rust `Result`, Zig error unions). Panics are allowed only in kernel pre-init and are documented per module. |
| 7 — No hard-coded assumptions | Target-dependent constants (page size, stack size, ports) live in one module per language (`kernel/src/arch`, bootloader config, `crypto/include/red/target.h`). |
| 8 — No stale documentation | Docs updated in the same commit as behavior change; review blocks doc-lag. |

## Conformance classes used in this repo

- **CEP-0** — cycle-exact hot code (future: FHE NTT inner loops, IPC copy loop,
  context switch). Requires measurement evidence.
- **CEP-1** — deterministic runtime code (current: AES/GCM core, kernel
  services). Deterministic, bounded, no hidden cost.
- **CEP-2** — offline tooling (build scripts, test generators, image tools).
- **CC** — everything else (docs, CI definitions).

## CEP header convention (all languages)

Every function that is CEP-0/CEP-1 or non-obvious carries a header block:

```
CEP: <class> | <Complete|Partial|Stub|Placeholder>
Cost: <complexity, memory behavior, allocations, locks, syscalls: explicit>
Fail: <explicit failure modes and how they are reported>
Assumes: <every assumption, each backed by a check or test>
```

Status markers are mandatory: never ship undocumented `Partial`/`Stub` code.

## Mechanical enforcement (current)

- C core: `-Wall -Wextra -Werror -pedantic` (host) and a freestanding compile
  check with `-ffreestanding -fno-builtin -mno-red-zone -mno-mmx -mno-sse2`
  (kernel-grade) plus an `nm` undefined-symbol check (zero undefined symbols
  = no hidden libc calls, link-level enforcement) in CI.
- NIST GCM vectors (TC13–16) + tamper detection tests must pass.
- Rust: `#![deny(warnings)]`-equivalent CI flags, `#![no_std]` scope checks
  (arrives with the kernel).
- Zig: `zig build` error-level warnings, explicit allocators.
- Isabelle: CI build of `proof/` sessions; `sorry` count tracked in the ledger
  (sorries are debt, each is listed with a closure plan).

## Waivers

None granted. Deviations require a signed waiver note in this file with a
closure milestone.
