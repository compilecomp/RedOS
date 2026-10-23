//! RedOS kernel — boot handoff contract.
//!
//! Fixed-layout structure produced by the Zig Stage-0 bootloader
//! (bootloader/src/main.zig) and consumed by the kernel entry point.
//! The Zig `Handoff` extern struct must match this `#[repr(C)]` layout
//! byte-for-byte. Layout enforcement: the magic/version check below plus
//! the boot test that reads a live banner out of QEMU.
//!
//! CEP: CEP-1 | Complete
//! Cost: passive data definitions; no code generated beyond accessor logic.
//! Fail: invalid magic/version is detected by `Handoff::validate()` and
//!       fails fast (kernel refuses to boot a corrupted handoff).
//! Assumes: little-endian x86_64; pointers are 8 bytes; handoff memory
//!          remains valid after ExitBootServices (EfiLoaderData pool).

/// Physical load base of the kernel image. MUST equal `KERNEL_BASE` in
/// kernel/linker.ld and bootloader/src/main.zig (checked at boot).
pub const KERNEL_BASE: u64 = 0x200000;

/// Magic: "RED0SHND" as ASCII little-endian.
pub const HANDOFF_MAGIC: u64 = 0x444E_4853_3044_4552; // "RED0SHND" (LE)

/// Handoff ABI version. Bump on any layout change; both sides check.
pub const HANDOFF_VERSION: u64 = 1;

/// Memory region classification (normalized from UEFI memory types).
pub const MEM_USABLE: u64 = 1;
#[allow(dead_code)] // ABI constant: defined by the bootloader contract (main.zig)
pub const MEM_RESERVED: u64 = 2;

/// One entry of the boot memory map, normalized from the UEFI memory map.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemEntry {
    /// Physical base address (bytes).
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
    /// `MEM_USABLE` or `MEM_RESERVED`.
    pub kind: u64,
}

/// Boot handoff. Produced by Zig bootloader, consumed by `_start`.
#[repr(C)]
pub struct Handoff {
    /// Must equal HANDOFF_MAGIC.
    pub magic: u64,
    /// Must equal HANDOFF_VERSION.
    pub version: u64,
    /// Physical base where the kernel image was loaded (== KERNEL_BASE).
    pub kernel_phys_base: u64,
    /// Top of the boot stack handed to the kernel (identity-mapped).
    pub stack_top: u64,
    /// Number of entries in the memory map array.
    pub mmap_len: u64,
    /// Pointer to `mmap_len` consecutive `MemEntry` values.
    pub mmap: *const MemEntry,
}

impl Handoff {
    /// CEP: CEP-1 | Complete
    /// Cost: O(1); validates magic, version and mmap pointer sanity.
    /// Fail: returns Err with a human-readable reason; caller must halt.
    /// Assumes: self is well-aligned (repr(C), pointer-aligned by design).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.magic != HANDOFF_MAGIC {
            return Err("bad handoff magic");
        }
        if self.version != HANDOFF_VERSION {
            return Err("unsupported handoff version");
        }
        if self.kernel_phys_base != KERNEL_BASE {
            return Err("kernel loaded at unexpected base");
        }
        if self.stack_top == 0 {
            return Err("null boot stack");
        }
        if self.mmap_len > 256 || self.mmap.is_null() {
            return Err("bad memory map");
        }
        Ok(())
    }

    /// CEP: CEP-1 | Complete
    /// Cost: O(mmap_len); read-only iteration.
    /// Fail: cannot fail (validate() must have passed).
    /// Assumes: mmap points to mmap_len consecutive MemEntry values.
    pub fn mem_entries(&self) -> &[MemEntry] {
        unsafe { core::slice::from_raw_parts(self.mmap, self.mmap_len as usize) }
    }
}
