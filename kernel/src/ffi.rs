//! RedOS kernel — C crypto core FFI (Tier-1 AES-256-GCM).
//!
//! The C core (`crypto/`) is linked statically into the kernel image and
//! runs freestanding (no libc). It is OUTSIDE the verified TCB by design:
//! a bug in the crypto core compromises only the data it processes, not
//! kernel mechanisms. The FFI surface is the exact `red/crypto.h` API with
//! named error codes mirroring `RED_CRYPTO_*`.
//!
//! CEP: CEP-1 | Complete (bindings only; cost/failure semantics live in the
//!                   C-side CEP headers of red/crypto.h)
//! Cost: per-call O(len); no heap; the C core is freestanding (nm-checked).
//! Fail: `RedCrypto` status codes map 1:1 to the C header's error contract.
//! Assumes: little-endian x86_64; `usize` == `size_t` (8 bytes); buffers
//!          obey the C-side aliasing/length contracts (tested in C, and by
//!          the kernel's IPC test end-to-end).

pub const RED_CRYPTO_OK: i32 = 0;
pub const RED_CRYPTO_ERR_NULL: i32 = -1;
pub const RED_CRYPTO_ERR_IVLEN: i32 = -2; // reserved (see C header)
pub const RED_CRYPTO_ERR_LEN: i32 = -3;
pub const RED_CRYPTO_ERR_AUTH: i32 = -4;

pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// XTS-AES-256 key length: data key K1 (32) || tweak key K2 (32).
pub const XTS_KEY_LEN: usize = 64;

extern "C" {
    fn red_aes256_gcm_encrypt(
        key: *const u8,
        iv: *const u8,
        pt: *const u8,
        pt_len: usize,
        aad: *const u8,
        aad_len: usize,
        ct: *mut u8,
        tag: *mut u8,
    ) -> i32;

    fn red_aes256_gcm_decrypt(
        key: *const u8,
        iv: *const u8,
        ct: *const u8,
        ct_len: usize,
        aad: *const u8,
        aad_len: usize,
        tag: *const u8,
        pt: *mut u8,
    ) -> i32;

    /* v0.6.0 additions — KMS substrate (see red/blake2b.h, red/argon2.h,
     * red/xts.h for the authoritative C-side contracts). */
    fn red_blake2b(
        out: *mut u8,
        out_len: usize,
        input: *const u8,
        in_len: usize,
        key: *const u8,
        key_len: usize,
    ) -> i32;

    fn red_argon2id(
        tag: *mut u8,
        tag_len: u32,
        pwd: *const u8,
        pwd_len: u32,
        salt: *const u8,
        salt_len: u32,
        secret: *const u8,
        secret_len: u32,
        ad: *const u8,
        ad_len: u32,
        passes: u32,
        memory_kib: u32,
        lanes: u32,
        work: *mut u8,
        work_len: u32,
    ) -> i32;

    fn red_xts256_encrypt(
        key: *const u8,
        data_unit: u64,
        pt: *const u8,
        len: usize,
        ct: *mut u8,
    ) -> i32;

    fn red_xts256_decrypt(
        key: *const u8,
        data_unit: u64,
        ct: *const u8,
        len: usize,
        pt: *mut u8,
    ) -> i32;

    /* Raw AES-256 block primitives (FIPS-197) — used by the kernel's
     * AES-256-CTR wipe stream (mm/phys.rs) and available to ring-0
     * callers that need the bare permutation. */
    fn red_aes256_init(ctx: *mut Aes256Ctx, key: *const u8) -> i32;
    fn red_aes256_encrypt_block(
        ctx: *const Aes256Ctx,
        input: *const u8,
        out: *mut u8,
    );
}

/// Rust mirror of `red_aes256_ctx` (crypto.h): 15 AES-256 round keys.
/// Layout is ABI: a size/offset mismatch would corrupt the C core's
/// schedule — pinned by the gcm round-trips (which share this struct in
/// C) and by the CTR-wipe round-trip in the boot scenario.
#[repr(C)]
pub struct Aes256Ctx {
    pub roundkeys: [u8; 240],
}

/// AES-256-CTR keystream block: ks = AES-256(counter_block).
/// CEP: CEP-1 | Complete
/// Cost: one key schedule + one encryption per context; 240 B of stack.
/// Fail: cannot fail (the C init validates nothing that can fail here —
///       key length is fixed by the type).
pub fn aes256_ctr_block(
    ctx: &mut Aes256Ctx,
    counter_block: &[u8; 16],
    ks: &mut [u8; 16],
) {
    unsafe {
        red_aes256_encrypt_block(ctx, counter_block.as_ptr(), ks.as_mut_ptr());
    }
}

/// Initialize an AES-256 context from a 32-byte key.
/// CEP: CEP-1 | Complete
/// Fail: cannot fail for a `[u8; 32]` key (the C contract's NULL case is
///       unreachable with a reference).
pub fn aes256_init(key: &[u8; KEY_LEN]) -> Aes256Ctx {
    let mut ctx = Aes256Ctx { roundkeys: [0; 240] };
    let rc = unsafe { red_aes256_init(&mut ctx, key.as_ptr()) };
    let _ = rc; // RED_CRYPTO_OK by construction (key is non-null, fixed len)
    ctx
}

/// Named wrapper around the C encrypt entry point.
/// CEP: CEP-1 | Complete
/// Fail: Err(code name) per the C contract; Ok(()) on RED_CRYPTO_OK.
pub fn gcm_encrypt(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    pt: &[u8],
    aad: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) -> Result<(), &'static str> {
    // Runtime capacity contract (debug_assert is compiled out of the
    // release kernel; an undersized ct would let the C core write past the
    // buffer in ring 0). Zero cost on the happy path.
    if ct.len() < pt.len() {
        return Err("LEN");
    }
    let rc = unsafe {
        red_aes256_gcm_encrypt(
            key.as_ptr(),
            iv.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            aad.as_ptr(),
            aad.len(),
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        )
    };
    status(rc)
}

/// Named wrapper around the C decrypt entry point.
/// CEP: CEP-1 | Complete
/// Fail: Err("AUTH") on tag mismatch — the C side zeroes `pt` (fail-closed).
pub fn gcm_decrypt(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    ct: &[u8],
    aad: &[u8],
    tag: &[u8; TAG_LEN],
    pt: &mut [u8],
) -> Result<(), &'static str> {
    if pt.len() < ct.len() {
        return Err("LEN");
    }
    let rc = unsafe {
        red_aes256_gcm_decrypt(
            key.as_ptr(),
            iv.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            aad.as_ptr(),
            aad.len(),
            tag.as_ptr(),
            pt.as_mut_ptr(),
        )
    };
    status(rc)
}

fn status(rc: i32) -> Result<(), &'static str> {
    match rc {
        RED_CRYPTO_OK => Ok(()),
        RED_CRYPTO_ERR_NULL => Err("NULL"),
        RED_CRYPTO_ERR_IVLEN => Err("IVLEN"),
        RED_CRYPTO_ERR_LEN => Err("LEN"),
        RED_CRYPTO_ERR_AUTH => Err("AUTH"),
        _ => Err("UNKNOWN"),
    }
}

/// One-shot keyed/plain BLAKE2b (RFC 7693) — the KMS derivation PRF.
/// CEP: CEP-1 | Complete
/// Fail: Err("NULL")/Err("LEN") per the C contract.
/// Assumes: out has room for out_len bytes (1..=64); key may be empty.
pub fn blake2b(
    out: &mut [u8],
    input: &[u8],
    key: &[u8],
) -> Result<(), &'static str> {
    if out.is_empty() || out.len() > 64 {
        return Err("LEN");
    }
    let rc = unsafe {
        red_blake2b(
            out.as_mut_ptr(),
            out.len(),
            input.as_ptr(),
            input.len(),
            key.as_ptr(),
            key.len(),
        )
    };
    status(rc)
}

/// Argon2id (RFC 9106) key derivation over a caller-provided work area.
/// CEP: CEP-1 | Complete
/// Fail: Err("NULL")/Err("LEN") per the C contract (all parameter checks
///       run BEFORE any computation — no partial tag is ever written).
/// Assumes: `work` is Locked-class memory the caller wipes afterwards
///       (see kms.rs — the work area carries password-derived state);
///       memory_kib/lanes satisfy the C header's floors.
pub fn argon2id(
    tag: &mut [u8],
    pwd: &[u8],
    salt: &[u8],
    passes: u32,
    memory_kib: u32,
    lanes: u32,
    work: &mut [u8],
) -> Result<(), &'static str> {
    if tag.is_empty() || tag.len() > 1024 {
        return Err("LEN");
    }
    let rc = unsafe {
        red_argon2id(
            tag.as_mut_ptr(),
            tag.len() as u32,
            pwd.as_ptr(),
            pwd.len() as u32,
            salt.as_ptr(),
            salt.len() as u32,
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            passes,
            memory_kib,
            lanes,
            work.as_mut_ptr(),
            work.len() as u32,
        )
    };
    status(rc)
}

/// XTS-AES-256 encrypt one data unit (sector) — storage-at-rest mode.
/// CEP: CEP-1 | Complete
/// Fail: Err("NULL")/Err("LEN") per the C contract (len must be a
///       positive multiple of 16 — no ciphertext stealing, SP 800-38E).
pub fn xts_encrypt(
    key: &[u8; XTS_KEY_LEN],
    data_unit: u64,
    pt: &[u8],
    ct: &mut [u8],
) -> Result<(), &'static str> {
    if ct.len() < pt.len() {
        return Err("LEN");
    }
    let rc = unsafe {
        red_xts256_encrypt(
            key.as_ptr(),
            data_unit,
            pt.as_ptr(),
            pt.len(),
            ct.as_mut_ptr(),
        )
    };
    status(rc)
}

/// XTS-AES-256 decrypt one data unit (sector).
/// CEP: CEP-1 | Complete
/// Fail: Err per the C contract; confidentiality-only (no tag — the RAM
///       disk's integrity story is its block table, see ramdisk.rs).
pub fn xts_decrypt(
    key: &[u8; XTS_KEY_LEN],
    data_unit: u64,
    ct: &[u8],
    pt: &mut [u8],
) -> Result<(), &'static str> {
    if pt.len() < ct.len() {
        return Err("LEN");
    }
    let rc = unsafe {
        red_xts256_decrypt(
            key.as_ptr(),
            data_unit,
            ct.as_ptr(),
            ct.len(),
            pt.as_mut_ptr(),
        )
    };
    status(rc)
}
