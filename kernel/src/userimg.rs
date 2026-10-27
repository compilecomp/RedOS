//! RedOS kernel — embedded user program images (v0.8.0).
//!
//! The ELF binaries are built by the Makefile from `usr/` BEFORE the
//! kernel target and linked into the kernel image here. They are the
//! manifests' content-hash subjects: the identity service hashes these
//! exact bytes (BLAKE2b-256) when staging spawn manifests, so what runs
//! is what was vouched for — the binary travels inside the kernel
//! because the Phase-2 RAM-disk has no filesystem to load from; the
//! hash binding is the authority, the embedding is the transport.
//!
//! Blindness note: these images contain the fast-path test protocol
//! constants (the payload the client sends and the server verifies).
//! That is the TEST's data — the ROUTER (fastpath.rs) has no reference
//! to them and never reads a payload word.
//!
//! CEP: CEP-2 | Complete (build-tooling data)
//! Cost: image-size bytes of .rodata.
//! Fail: a missing image fails the KERNEL BUILD (include_bytes! is
//!       compile-time — no runtime absence to defend against).

/// Fast-path server: PING round trip, then a register-path RECV whose
/// payload it verifies against its own protocol constants, then exit 0.
pub static SRV_ELF: &[u8] = include_bytes!("../../build/usr/srv.elf");

/// Fast-path client: PING round trip, then a register-path SEND of the
/// protocol constants, then exit 0.
pub static CLI_ELF: &[u8] = include_bytes!("../../build/usr/cli.elf");

/// Fault-containment demo: dereferences an unmapped address in ring 3 —
/// the kernel must contain the #PF and keep everything else running.
pub static FAULTY_ELF: &[u8] = include_bytes!("../../build/usr/faulty.elf");
