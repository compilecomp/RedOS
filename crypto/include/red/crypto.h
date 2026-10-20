/* RedOS crypto core — public API.
 *
 * Tier-1 cryptography: AES-256 and AES-256-GCM per NIST SP 800-38D.
 * Freestanding C11: no libc, no dynamic allocation, no locks, no syscalls.
 * This core is OUTSIDE the verified TCB (userspace-linkable, kernel-linkable).
 *
 * CEP&CC: this file is the contract for CEP-1 code. Every function documents
 * cost, failure, and assumptions at its definition site. Failure contracts in
 * this header are enforced by tests/crypto/test_vectors.c (Law 3).
 */
#ifndef RED_CRYPTO_H
#define RED_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. Every function returns RED_CRYPTO_OK or exactly one error.
 * Values are ABI-stable; never renumber, only append. */
#define RED_CRYPTO_OK        0
#define RED_CRYPTO_ERR_NULL  (-1) /* required pointer argument was NULL        */
#define RED_CRYPTO_ERR_IVLEN (-2) /* RESERVED (Phase 1 API is fixed-96-bit IV; \
                                   * not produced; kept for ABI stability)    */
#define RED_CRYPTO_ERR_LEN   (-3) /* data length over SP 800-38D cap, or      \
                                   * partial in/out overlap (exact in-place   \
                                   * is allowed, see below)                   */
#define RED_CRYPTO_ERR_AUTH  (-4) /* GCM tag mismatch (ciphertext tampering)   */

#define RED_CRYPTO_KEY_LEN   32u  /* AES-256 key size in bytes */
#define RED_CRYPTO_IV_LEN    12u  /* GCM 96-bit IV (SP 800-38D §8.2.1) */
#define RED_CRYPTO_TAG_LEN   16u  /* GCM tag size in bytes */
#define RED_CRYPTO_BLOCK_LEN 16u  /* AES block size in bytes */

/* SP 800-38D §5.2.1.1 GCM data cap: 2^39 - 256 bits = 2^36 - 32 bytes.
 * Inputs above this are rejected with RED_CRYPTO_ERR_LEN. */
#define RED_CRYPTO_MAX_DATA  (((uint64_t)1 << 36) - 32u)

/* AES-256 block cipher context: 15 round keys, 240 bytes. */
typedef struct {
	uint8_t roundkeys[240];
} red_aes256_ctx;

/* AES S-box, exported for test-time independent verification (Law 3). */
extern const uint8_t red_aes256_sbox[256];

/*
 * CEP: CEP-1 | Complete
 * Cost: 240 B into *ctx + 32 B read; O(1); no alloc, no locks.
 * Fail: RED_CRYPTO_ERR_NULL if ctx or key is NULL.
 * Assumes: (otherwise unchecked) key is readable for 32 bytes.
 */
int red_aes256_init(red_aes256_ctx *ctx, const uint8_t key[RED_CRYPTO_KEY_LEN]);

/*
 * CEP: CEP-1 | Complete
 * Cost: fixed 14 rounds, ~500 table lookups, 16 B in / 16 B out; no alloc.
 * Fail: cannot fail.
 * Assumes: in and out do not partially overlap (exact aliasing is fine);
 *          ctx was initialized by red_aes256_init.
 */
void red_aes256_encrypt_block(const red_aes256_ctx *ctx,
                              const uint8_t in[RED_CRYPTO_BLOCK_LEN],
                              uint8_t out[RED_CRYPTO_BLOCK_LEN]);

/*
 * CEP: CEP-1 | Complete
 * Cost: O(pt_len) AES blocks; two key schedules run sequentially; peak stack
 *       <= 512 B; no heap, no locks, no syscalls.
 * Fail: RED_CRYPTO_ERR_NULL (key/iv/tag NULL, or pt/ct NULL with pt_len>0),
 *       RED_CRYPTO_ERR_LEN (pt_len or aad_len > RED_CRYPTO_MAX_DATA, or
 *       partial pt/ct overlap — exact in-place pt==ct IS supported),
 *       (lengths are validated before any pointer is dereferenced).
 * Assumes: iv is readable for exactly RED_CRYPTO_IV_LEN bytes (fixed-96-bit
 *          API; unchecked at runtime by design — see ERR_IVLEN note);
 *          ct buffer has room for pt_len bytes; tag buffer 16 bytes.
 * Effects: ct = GCM-encrypt(pt); tag authenticates aad ∥ ct.
 * Zeroization: round-key context and keystream are wiped before return
 *          (Phase 1 hardening decision, tested implicitly by round-trips).
 */
int red_aes256_gcm_encrypt(const uint8_t key[RED_CRYPTO_KEY_LEN],
                           const uint8_t iv[RED_CRYPTO_IV_LEN],
                           const uint8_t *pt, size_t pt_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ct, uint8_t tag[RED_CRYPTO_TAG_LEN]);

/*
 * CEP: CEP-1 | Complete
 * Cost: O(ct_len) AES blocks; two key schedules run sequentially; peak stack
 *       <= 512 B; no heap, no locks, no syscalls.
 * Fail: RED_CRYPTO_ERR_NULL, RED_CRYPTO_ERR_LEN (same rules as encrypt),
 *       RED_CRYPTO_ERR_AUTH (tag mismatch: pt is then fully zeroed).
 * Assumes: iv readable for exactly RED_CRYPTO_IV_LEN bytes; pt buffer has
 *          room for ct_len bytes; exact in-place ct==pt IS supported.
 * Effects: verifies tag in constant time BEFORE producing pt (no plaintext
 *          release on unauthenticated input — fail-closed).
 */
int red_aes256_gcm_decrypt(const uint8_t key[RED_CRYPTO_KEY_LEN],
                           const uint8_t iv[RED_CRYPTO_IV_LEN],
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t tag[RED_CRYPTO_TAG_LEN],
                           uint8_t *pt);

#ifdef __cplusplus
}
#endif
#endif /* RED_CRYPTO_H */
