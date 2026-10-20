//! Minimal ELF64 loader-validation for the RedOS kernel image.
//!
//! Supports exactly what the kernel produces: ET_EXEC, x86_64, little-endian,
//! PT_LOAD segments addressed at fixed physical addresses in [base, max).
//! Anything else is rejected with a named error (fail-fast, CEP&CC Law 6).
//!
//! CEP: CEP-1 | Complete
//! Cost: O(phnum) validation + O(filesz) copy performed by the caller.
//! Fail: named ElfError for every malformed-input class; no panics.
//! Assumes: little-endian host (x86_64); input slice is fully read.

const std = @import("std");
const uefi = std.os.uefi;

const EHDR_SIZE = 64;
const PHDR_SIZE = 56;
const MAX_SEGMENTS = 16;

pub const Segment = struct {
    /// Physical destination address (identity-mapped).
    paddr: u64,
    /// Offset of segment data within the file slice.
    offset: u64,
    /// Bytes to copy from file.
    filesz: u64,
    /// Bytes in memory (filesz + zero-filled tail).
    memsz: u64,
};

pub const Image = struct {
    entry: u64,
    segments: []const Segment,
    /// One past the highest loaded byte.
    mem_end: u64,
};

pub const ElfError = error{
    TooSmall,
    BadMagic,
    BadClass,
    BadEndian,
    BadType,
    BadMachine,
    BadPhoff,
    TooManySegments,
    NoLoadableSegments,
    SegmentOutsideWindow,
    SegmentTooBig,
    SegmentOverlap,
    BadFileSize,
};

/// Map ELF errors onto UEFI statuses for the bootloader's `die` reporting.
pub fn errToStatus(e: ElfError) uefi.Status {
    return switch (e) {
        error.TooSmall, error.BadMagic, error.BadClass, error.BadEndian => .Unsupported,
        error.BadType, error.BadMachine, error.BadPhoff => .Unsupported,
        error.TooManySegments, error.NoLoadableSegments => .Unsupported,
        error.SegmentOutsideWindow, error.SegmentTooBig, error.SegmentOverlap => .InvalidParameter,
        error.BadFileSize => .InvalidParameter,
    };
}

fn readU16(data: []const u8, off: usize) u64 {
    return std.mem.readInt(u16, data[off..][0..2], .little);
}

fn readU32(data: []const u8, off: usize) u64 {
    return std.mem.readInt(u32, data[off..][0..4], .little);
}

fn readU64(data: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, data[off..][0..8], .little);
}

/// Segment collection storage. Module-level static (NOT a local): the
/// returned slice outlives parse() in the single-threaded boot context.
var segments: [MAX_SEGMENTS]Segment = undefined;

/// CEP: CEP-1 | Complete
/// Cost: O(phnum); validation only (caller copies bytes).
/// Fail: named ElfError per malformed-input class.
/// Assumes: data is the complete kernel file; single-threaded boot; the
///          returned slice aliases module state (documented above).
pub fn parse(data: []const u8, base: u64, max: u64) ElfError!Image {
    if (data.len < EHDR_SIZE) return error.TooSmall;
    if (!std.mem.eql(u8, data[0..4], "\x7fELF")) return error.BadMagic;
    if (data[4] != 2) return error.BadClass; // ELF64
    if (data[5] != 1) return error.BadEndian; // little-endian
    if (readU16(data, 16) != 2) return error.BadType; // ET_EXEC
    if (readU16(data, 18) != 62) return error.BadMachine; // x86-64

    const phoff = readU64(data, 32);
    const phentsize = readU16(data, 54);
    const phnum = readU16(data, 56);

    if (phentsize != PHDR_SIZE) return error.BadPhoff;
    if (phnum == 0 or phnum > 128) return error.BadPhoff;
    // Saturating arithmetic: crafted near-2^64 values must yield a named
    // error, not a ReleaseSafe overflow panic (CEP header: no panics).
    const dlen: u64 = data.len;
    if (phoff > dlen or phnum *| PHDR_SIZE > dlen -| phoff) return error.BadPhoff;

    var n: usize = 0;
    var mem_end: u64 = base;

    for (0..@intCast(phnum)) |i| {
        const h = phoff + i * PHDR_SIZE;
        const p_type = readU32(data, h);
        if (p_type != 1) continue; // PT_LOAD only

        const p_offset = readU64(data, h + 8);
        const p_paddr = readU64(data, h + 24);
        const p_filesz = readU64(data, h + 32);
        const p_memsz = readU64(data, h + 40);

        if (p_filesz > p_memsz) return error.SegmentTooBig;
        if (p_offset > dlen or p_filesz > dlen -| p_offset) return error.BadFileSize;
        if (p_memsz == 0) continue;
        if (p_paddr < base or p_paddr > max or p_memsz > max -| p_paddr) return error.SegmentOutsideWindow;

        // Reject aliasing segments (Law 2: stated AND checked).
        for (segments[0..n]) |s| {
            const a_lo = s.paddr;
            const a_hi = s.paddr + s.memsz; // bounded by window check above
            const b_lo = p_paddr;
            const b_hi = p_paddr + p_memsz;
            if (a_lo < b_hi and b_lo < a_hi) return error.SegmentOverlap;
        }

        if (n >= MAX_SEGMENTS) return error.TooManySegments;
        segments[n] = .{
            .paddr = p_paddr,
            .offset = p_offset,
            .filesz = p_filesz,
            .memsz = p_memsz,
        };
        if (p_paddr + p_memsz > mem_end) mem_end = p_paddr + p_memsz;
        n += 1;
    }

    if (n == 0) return error.NoLoadableSegments;

    const entry = readU64(data, 24);
    if (entry < base or entry >= mem_end) return error.SegmentOutsideWindow;

    return .{
        .entry = entry,
        .segments = segments[0..n],
        .mem_end = mem_end,
    };
}
