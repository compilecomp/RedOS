//! RedOS kernel — structural audit surface (Phase 2).
//!
//! The anti-swap guarantee (mm/phys.rs) is structural: the kernel links
//! no storage driver. `EXPORTED_SYMBOLS` is the *declared* external
//! surface of the kernel, reviewed at `phys::anti_swap_audit()` boot time.
//! If a future phase ever links a block-device module, it must appear
//! here — and the audit will then refuse to boot (Law 6: a sovereignty
//! guarantee broken silently is worse than no guarantee).
//!
//! CEP: CEP-2 | Complete (declarative inventory)

/// Declared kernel external surface (substring-level names; the audit
/// scans for storage-path indicators: ahci/nvme/ata_/sdhci).
pub const EXPORTED_SYMBOLS: [&str; 12] = [
    "uart16550(port-io)",       // serial console (the only I/O)
    "uart16550(rx-input)",      // operator input service (v0.7.0: polled RX,
                                //  masked-echo PIN entry, no secret constants)
    "aes-gcm(xts-none)",        // C core, comms crypto (no storage mode)
    "pagemap(mmu)",             // MMU management
    "ephemeral-alloc(ram)",     // RAM-only allocator
    "ipc(blind-router)",        // capability IPC
    "kms(argon2id-vault)",      // RAM-only KMS vault (v0.6.0: sealed blob,
                                //  duress dead-man wipe, BLAKE2b-KDF leases;
                                //  v0.7.0: owner-bound leases, RNG policy)
    "ramdisk(xts-256-volatile)",// XTS RAM disk — RAM frames only, no block
                                //  device, no persistence path (v0.6.0);
                                //  authority-gated I/O via the tracker (v0.7.0)
    "identity(zero-id)",        // Zero-ID identity (v0.7.0: content-hash
                                //  manifests, sandbox spawner, Permission
                                //  Tracker, operator prompt handshake — no
                                //  IDs, no PKI, vault-anchored trust)
    "syscomm(sysret-fastpath)", // v0.8.0: syscall/sysret ring boundary,
                                //  register fast path (blind payload
                                //  routing), ring-3 ELF tasks, fault
                                //  containment — no port I/O, no DMA
    "glass(compositor-ro)",     // v0.8.0: compositor with read-only panes;
                                //  display path is RAM frames only
    "pcid(invlpg-type2)",       // v0.8.0: PCID+INVPCID pair (TLB
                                //  invalidation obligation; full-flush
                                //  baseline when the pair is absent)
];
