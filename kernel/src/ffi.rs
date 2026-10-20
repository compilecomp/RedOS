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
