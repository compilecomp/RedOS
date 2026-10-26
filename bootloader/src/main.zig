//! RedOS Stage-0 UEFI bootloader (Zig, x86_64) — Layer 0.
//!
//! Boot chain: OVMF → this EFI app → RedOS kernel.
//!   1. Open the EFI System Partition, read `\redos.bin` (kernel ELF64).
//!   2. Parse + validate the ELF; copy PT_LOAD segments to fixed physical
//!      addresses (identity mapping; KERNEL_BASE must match kernel/linker.ld).
//!   3. Build fresh page tables (2 MiB pages, identity map of low 1 GiB —
//!      every loader-placed structure lives below 0x40000000 by construction
//!      and the placement is asserted before the jump).
//!   4. Normalize the UEFI memory map (stride-honoring), build the handoff,
//!      ExitBootServices.
//!   5. cli, load CR3, switch to the boot stack, jump to the kernel entry
//!      with the handoff pointer in RDI (SysV).
//!
//! CEP: CEP-1 | Complete (v0.2.0 scope; TPM measurement is a documented
//!                   stub — see ARCHITECTURE.md decision log)
//! Cost: one-shot boot path; O(ELF size + memory map size); no heap.
//! Fail: every UEFI status is checked; failure prints a named stage + status
//!       on serial (direct port I/O to 0x3F8, valid pre-EBS) and halts.
//! Assumes: OVMF/QEMU x86_64; kernel is ET_EXEC linked at KERNEL_BASE;
//!          ESP is the boot volume; 2 MiB pages suffice for Phase 1;
//!          single-threaded boot context (static buffers are safe).

const std = @import("std");
const uefi = std.os.uefi;

const elf = @import("elf.zig");

/// Kernel load base — MUST match kernel/linker.ld KERNEL_BASE.
const KERNEL_BASE: u64 = 0x200000;
/// Load window end; bootloader enforces, linker ASSERTs the same bound.
const KERNEL_MAX: u64 = 0x600000;
/// Fixed boot stack: 64 KiB at 256 MiB (low RAM, identity-mapped).
const STACK_BASE: u64 = 0x10000000;
const STACK_PAGES: usize = 16;
/// Kernel file buffer at 128 MiB: fixed placement so the buffer can NEVER
/// overlap the kernel load window (the @memcpy-alias failure mode).
const FILE_BUF_BASE: u64 = 0x08000000;
const FILE_POOL_SIZE: usize = 8 * 1024 * 1024;
const FILE_POOL_PAGES: usize = FILE_POOL_SIZE >> 12;
/// Page tables at 272 MiB (fixed, above file buffer and boot stack):
/// exactly 3 pages — one PML4, one PDPT, one PD covering the low 1 GiB.
const PT_BASE: u64 = 0x11000000;
const PT_PAGES: usize = 3;

const HANDOFF_MAGIC: u64 = 0x444E_4853_3044_4552; // "RED0SHND" (LE)
const HANDOFF_VERSION: u64 = 1;
const HANDOFF_DESC_VER: u32 = 1; // expected UEFI memory map version

const MEM_USABLE: u64 = 1;
const MEM_RESERVED: u64 = 2;

/// Capacity of the normalized handoff map. MUST equal the kernel's
/// `Handoff::validate` bound (kernel/src/handoff.rs). Firmware maps are
/// COALESCED into maximal same-kind regions (see collect_map), so this
/// bound is comfortable for any realistic firmware — but it stays a
/// named error if exceeded (never a silent truncation). The original
/// 128-entry hard cap died on CI runners whose OVMF emitted >128 raw
/// descriptors (v0.7.0 repair; local QEMU emitted exactly 123).
const MAX_MMAP_ENTRIES: usize = 256;

/// UEFI memory types we normalize to MEM_USABLE (everything else is
/// reserved). Module scope: shared by both memory-map walks.
const T_LOADER_CODE: u32 = 1;
const T_LOADER_DATA: u32 = 2;
const T_BS_CODE: u32 = 3;
const T_BS_DATA: u32 = 4;
const T_CONVENTIONAL: u32 = 7;

const MemEntry = extern struct {
    base: u64,
    len: u64,
    kind: u64,
};

/// Must match kernel/src/handoff.rs `Handoff` (#repr(C)) byte-for-byte.
const Handoff = extern struct {
    magic: u64,
    version: u64,
    kernel_phys_base: u64,
    stack_top: u64,
    mmap_len: u64,
    mmap: [*]const MemEntry,
};

/// Normalized memory map storage (bootloader image memory, persists post-EBS).
var mmap_entries: [MAX_MMAP_ENTRIES]MemEntry = undefined;

/// Walk the firmware descriptor buffer into the static handoff map,
/// COALESCING contiguous same-kind regions into maximal ones. Firmware
/// fragmentation (MMIO holes, boot-services granularity) can exceed any
/// fixed entry budget; the kernel contract needs maximal regions, not
/// firmware bookkeeping. Returns the coalesced entry count; dies with a
/// named error only if even the coalesced map exceeds the table (no
/// silent truncation, ever).
/// CEP: CEP-1 | Complete (v0.7.0: extracted from the duplicated walks)
/// Cost: O(descriptors).
/// Fail: die("memory map overflow") when MAX_MMAP_ENTRIES is exceeded.
fn collect_map(buf: [*]const u8, desc_size: usize, count: usize) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const rec = buf + i * desc_size;
        // EFI_MEMORY_DESCRIPTOR field offsets (little-endian):
        //   type @ 0 (u32), physical_start @ 8 (u64), number_of_pages @ 24 (u64)
        const d_type = std.mem.readInt(u32, rec[0..4], .little);
        const phys = std.mem.readInt(u64, rec[8..16], .little);
        const pages = std.mem.readInt(u64, rec[24..32], .little);
        const len = pages *| 0x1000;
        if (len == 0) continue;
        const kind: u64 = switch (d_type) {
            T_LOADER_CODE, T_LOADER_DATA, T_BS_CODE, T_BS_DATA, T_CONVENTIONAL => MEM_USABLE,
            else => MEM_RESERVED,
        };
        // Contiguous extension of the previous same-kind region? Merge
        // (saturating arithmetic: an overflowing base+len can never equal
        // phys, so the merge simply does not fire).
        if (n > 0) {
            const prev = &mmap_entries[n - 1];
            if (prev.kind == kind and prev.base +| prev.len == phys) {
                prev.len +|= len;
                continue;
            }
        }
        if (n >= MAX_MMAP_ENTRIES) die("memory map overflow", .OutOfResources);
        mmap_entries[n] = .{
            .base = phys,
            .len = len,
            .kind = kind,
        };
        n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Serial debug output (direct 16550 port I/O; works before ExitBootServices)
// ---------------------------------------------------------------------------

inline fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[v], %[p]"
        :
        : [v] "{al}" (val),
          [p] "{dx}" (port),
    );
}

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[p], %[r]"
        : [r] "={al}" (-> u8),
        : [p] "{dx}" (port),
    );
}

fn serial_init() void {
    outb(0x3F8 + 1, 0x00); // IER: polled mode
    outb(0x3F8 + 3, 0x80); // LCR: DLAB on
    outb(0x3F8 + 0, 0x01); // divisor low: 115200
    outb(0x3F8 + 1, 0x00); // divisor high
    outb(0x3F8 + 3, 0x03); // 8N1
    outb(0x3F8 + 2, 0xC7); // FIFO
    outb(0x3F8 + 4, 0x0B); // MCR
}

fn serial_write(s: []const u8) void {
    for (s) |b| {
        while ((inb(0x3F8 + 5) & 0x20) == 0) {}
        outb(0x3F8, b);
    }
}

fn serial_hex(v: u64) void {
    const digits = "0123456789abcdef";
    var i: u6 = 60;
    while (true) {
        const one = [_]u8{digits[@intCast((v >> i) & 0xF)]};
        serial_write(&one);
        if (i == 0) break;
        i -= 4;
    }
}

/// Named-failure exit: print stage + UEFI status, halt forever (no return).
fn die(stage: []const u8, status: uefi.Status) noreturn {
    serial_write("\n[REDOS-BOOT] FAIL: ");
    serial_write(stage);
    serial_write(" status=0x");
    serial_hex(@intFromEnum(status));
    serial_write("\n");
    while (true) {
        asm volatile ("hlt");
    }
}

// ---------------------------------------------------------------------------
// Boot main
// ---------------------------------------------------------------------------

/// CEP: CEP-1 | Complete
/// Cost: one-shot boot; O(ELF + memory map).
/// Fail: dies via `die()` with a named stage on any UEFI or ELF error.
pub fn main() usize {
    serial_init();
    serial_write("\n[REDOS-BOOT] stage-0 UEFI bootloader\n");

    const bs = uefi.system_table.boot_services.?;

    // --- 1. Open the kernel file on the ESP -------------------------------
    const li = bs.openProtocolSt(uefi.protocol.LoadedImage, uefi.handle) catch
        die("open LoadedImage", .LoadError);
    const device = li.device_handle orelse die("no device handle", .Unsupported);

    const sfs = bs.openProtocolSt(uefi.protocol.SimpleFileSystem, device) catch
        die("open SimpleFileSystem", .Unsupported);

    var root: *const uefi.protocol.File = undefined;
    if (sfs.openVolume(&root) != .Success) die("openVolume", .VolumeCorrupted);

    var kernel_file: *const uefi.protocol.File = undefined;
    if (root.open(
        &kernel_file,
        std.unicode.utf8ToUtf16LeStringLiteral("\\redos.bin"),
        uefi.protocol.File.efi_file_mode_read,
        0,
    ) != .Success) die("open \\redos.bin", .NotFound);

    // --- 2. Read the whole kernel image into a fixed buffer -----------------
    var file_buf: [*]align(4096) u8 = @ptrFromInt(FILE_BUF_BASE);
    if (bs.allocatePages(.AllocateAddress, .LoaderData, FILE_POOL_PAGES, &file_buf) != .Success)
        die("allocatePages(file buffer)", .OutOfResources);

    var total: usize = 0;
    while (total < FILE_POOL_SIZE) {
        var chunk: usize = FILE_POOL_SIZE - total;
        if (kernel_file.read(&chunk, file_buf + total) != .Success)
            die("read kernel", .DeviceError);
        if (chunk == 0) break;
        total += chunk;
    }
    serial_write("[REDOS-BOOT] kernel file bytes: ");
    serial_hex(total);
    serial_write("\n");

    // --- 3. Parse + validate the ELF ---------------------------------------
    const img = elf.parse(file_buf[0..total], KERNEL_BASE, KERNEL_MAX) catch |e|
        die("parse ELF", elf.errToStatus(e));
    serial_write("[REDOS-BOOT] ELF entry: 0x");
    serial_hex(img.entry);
    serial_write("\n");

    // --- 4. Allocate the load window at KERNEL_BASE ------------------------
    const load_pages: usize = @intCast((KERNEL_MAX - KERNEL_BASE) >> 12);
    var kmem: [*]align(4096) u8 = @ptrFromInt(KERNEL_BASE);
    if (bs.allocatePages(.AllocateAddress, .LoaderData, load_pages, &kmem) != .Success)
        die("allocatePages(kernel window)", .OutOfResources);

    // Copy PT_LOAD segments; zero the tails (BSS).
    for (img.segments) |seg| {
        const dst: [*]u8 = @ptrFromInt(seg.paddr);
        const src = file_buf + seg.offset;
        @memcpy(dst[0..seg.filesz], src[0..seg.filesz]);
        @memset(dst[seg.filesz..seg.memsz], 0);
    }
    serial_write("[REDOS-BOOT] segments loaded, image end 0x");
    serial_hex(img.mem_end);
    serial_write("\n");

    // --- 5. Boot stack ------------------------------------------------------
    var stack_mem: [*]align(4096) u8 = @ptrFromInt(STACK_BASE);
    if (bs.allocatePages(.AllocateAddress, .LoaderData, STACK_PAGES, &stack_mem) != .Success)
        die("allocatePages(stack)", .OutOfResources);
    const stack_top: u64 = STACK_BASE + STACK_PAGES * 0x1000;

    // --- 6. Page tables: identity map low 1 GiB with 2 MiB pages -----------
    // Layout: 1 PML4 + 1 PDPT + 1 PD (only the low 1 GiB is mapped:
    // kernel 0x200000, stack 0x10000000, all loader memory below 1 GiB).
    var pt_mem: [*]align(4096) u8 = @ptrFromInt(PT_BASE);
    if (bs.allocatePages(.AllocateAddress, .LoaderData, PT_PAGES, &pt_mem) != .Success)
        die("allocatePages(page tables)", .OutOfResources);

    const pml4_phys = @intFromPtr(pt_mem);
    const pdpt_phys = pml4_phys + 0x1000;
    const pd0_phys = pml4_phys + 0x2000;

    const pml4: [*]u64 = @ptrFromInt(pml4_phys);
    const pdpt: [*]u64 = @ptrFromInt(pdpt_phys);
    const pd0: [*]u64 = @ptrFromInt(pd0_phys);

    @memset(pt_mem[0 .. PT_PAGES * 0x1000], 0);

    pml4[0] = pdpt_phys | 0x03; // present | writable
    pdpt[0] = pd0_phys | 0x03; // PDPT[0] -> PD (covers 0..1 GiB)
    // 2 MiB pages: present | writable | page-size
    for (0..512) |j| {
        pd0[j] = @as(u64, @intCast(j)) << 21 | 0x83;
    }
    // PDPT[1..3] left unmapped: Phase 1 only needs the low 1 GiB
    // (kernel 0x200000, stack 0x10000000, page tables all below 1 GiB).

    serial_write("[REDOS-BOOT] page tables @ 0x");
    serial_hex(pml4_phys);
    serial_write("\n");

    // --- 7. Memory map + handoff -------------------------------------------
    // Fixed 64 KiB descriptor buffer (~1600 entries at 40 B): one attempt,
    // no probe/allocate/retry dance that can itself grow the map. If this
    // still returns BufferTooSmall the platform is out of scope for Phase 1.
    const MMAP_BUF_SIZE: usize = 65536;
    var mmap_size: usize = MMAP_BUF_SIZE;
    var map_key: usize = 0;
    var desc_size: usize = 0;
    var desc_ver: u32 = 0;

    var mmap_buf: [*]align(8) u8 = undefined;
    if (bs.allocatePool(.LoaderData, MMAP_BUF_SIZE, &mmap_buf) != .Success)
        die("allocatePool(mmap)", .OutOfResources);

    var st = bs.getMemoryMap(&mmap_size, @ptrCast(mmap_buf), &map_key, &desc_size, &desc_ver);
    if (st != .Success) die("getMemoryMap", st);
    if (desc_size < 40) die("memory map stride < 40", .Unsupported);
    if (desc_ver != HANDOFF_DESC_VER) die("memory map version != 1", .IncompatibleVersion);

    // Firmware may report a stride LARGER than sizeof(EFI_MEMORY_DESCRIPTOR)
    // (OVMF reports 48 for a 40-byte struct). The spec mandates walking with
    // the reported stride, so fields are read at fixed offsets within each
    // record instead of via a pointer-typed array (which would assume 40).
    const desc_count = mmap_size / desc_size;
    // EFI_MEMORY_DESCRIPTOR field offsets (little-endian):
    //   type @ 0 (u32), physical_start @ 8 (u64), number_of_pages @ 24 (u64)
    // Coalesced, normalized map (maximal same-kind regions; see collect_map).
    // The kernel contract needs maximal regions, not firmware bookkeeping —
    // and a coalesced map fits the fixed handoff table on any realistic
    // firmware (v0.7.0 repair: raw maps overflowed 128 entries on CI).
    const n = collect_map(mmap_buf, desc_size, desc_count);
    serial_write("[REDOS-BOOT] memory map: ");
    serial_hex(n);
    serial_write(" entries (stride ");
    serial_hex(desc_size);
    serial_write(")\n");

    var handoff = Handoff{
        .magic = HANDOFF_MAGIC,
        .version = HANDOFF_VERSION,
        .kernel_phys_base = KERNEL_BASE,
        .stack_top = stack_top,
        .mmap_len = n,
        .mmap = &mmap_entries,
    };

    // --- 8. ExitBootServices (with the spec-mandated retry) -----------------
    st = bs.exitBootServices(uefi.handle, map_key);
    if (st == .InvalidParameter) {
        // Map changed under us: re-query and retry exactly once (allowed per
        // spec after an unsuccessful EBS). The handoff MUST be rebuilt from
        // the fresh map — booting with a stale map is silent wrongness.
        mmap_size = MMAP_BUF_SIZE;
        st = bs.getMemoryMap(&mmap_size, @ptrCast(mmap_buf), &map_key, &desc_size, &desc_ver);
        if (st != .Success) die("getMemoryMap(retry)", st);
        if (desc_size < 40) die("memory map stride < 40 (retry)", .Unsupported);
        if (desc_ver != HANDOFF_DESC_VER) die("memory map version != 1 (retry)", .IncompatibleVersion);
        const rc2 = mmap_size / desc_size;
        const m = collect_map(mmap_buf, desc_size, rc2);
        handoff.mmap_len = m;
        st = bs.exitBootServices(uefi.handle, map_key);
    }
    if (st != .Success) die("exitBootServices", st);

    // --- 9. Jump -------------------------------------------------------------
    // Boot services are gone. Serial still works (port I/O). CR3, stack,
    // handoff pointer (RDI), then entry. Never returns.
    // Portability guard: everything the kernel dereferences (handoff, map
    // entries, stack, page tables) must be inside the identity-mapped 1 GiB.
    if (@intFromPtr(&handoff) >= 0x40000000) die("handoff above identity map", .Unsupported);
    if (@intFromPtr(&mmap_entries) >= 0x40000000) die("map entries above identity map", .Unsupported);
    serial_write("[REDOS-BOOT] jumping to kernel\n");

    // All operands pinned to explicit registers: no allocator choice can
    // collide with the RBP zeroing below (rbp listed as clobbered anyway).
    asm volatile (
        \\ cli
        \\ movq %[cr3], %%cr3
        \\ movq %[stack], %%rsp
        \\ xorq %%rbp, %%rbp
        \\ call *%[entry]
        \\ ud2
        :
        : [cr3] "{rbx}" (pml4_phys),
          [stack] "{rcx}" (stack_top),
          [hoff] "{rdi}" (&handoff),
          [entry] "{rsi}" (img.entry),
        : "memory", "rbp"
    );

    unreachable;
}
