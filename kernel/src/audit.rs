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
pub const EXPORTED_SYMBOLS: [&str; 7] = [
    "uart16550(port-io)",       // serial console (the only I/O)
    "aes-gcm(xts-none)",        // C core, comms crypto (no storage mode)
    "pagemap(mmu)",             // MMU management
    "ephemeral-alloc(ram)",     // RAM-only allocator
    "ipc(blind-router)",        // capability IPC
    "kms(argon2id-vault)",      // RAM-only KMS vault (v0.6.0: sealed blob,
                                //  duress dead-man wipe, BLAKE2b-KDF leases)
    "ramdisk(xts-256-volatile)",// XTS RAM disk — RAM frames only, no block
                                //  device, no persistence path (v0.6.0)
];
