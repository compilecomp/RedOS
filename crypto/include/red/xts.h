/* RedOS crypto core — XTS-AES-256 (NIST SP 800-38E / IEEE 1619-2007),
 * the storage-at-rest mode of the RAM-only KMS vault.
 *
 * CEP: CEP-1 | Complete
 * Cost: 2 AES key schedules per call + one AES block per 16 data bytes;
 *       one GF(2^128) doubling per block; no alloc, no locks.
 * Fail: named errors, validated before any byte is touched (fail-closed).
 * Assumes: little/big-endian irrelevant (byte-oriented); data_unit is the
 *       sector number encoded as a 128-bit little-endian integer (IEEE
 *       1619 convention).
 *
 * Scope decision (documented, CEP&CC Law 7): this core implements the
 * NIST-approved subset of XTS-AES (SP 800-38E): data units are a whole
 * number of 16-byte AES blocks and at least 16 bytes long. The IEEE
 * 1619-2007 ciphertext-stealing extension for a partial final block is
 * deliberately NOT provided — a caller with a partial unit gets a named
 * error (RED_CRYPTO_ERR_LEN), never improvised crypto. RedOS RAM-disk
 * sectors are 512-byte multiples, which is squarely inside this subset.
 */
#ifndef RED_XTS_H
#define RED_XTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* XTS-AES-256 key = data key (K1) || tweak key (K2), 32 bytes each. */
#define RED_XTS256_KEY_LEN 64u
/* Minimum data unit: one AES block (SP 800-38E: >= 2^128 bits). */
#define RED_XTS256_UNIT_MIN 16u

/*
 * XTS-AES-256 encrypt one data unit in place or to a separate buffer.
 *
 * CEP: CEP-1 | Complete
 * Cost: O(len/16) AES encryptions; 256 B of key schedules on stack.
 * Fail: RED_CRYPTO_ERR_NULL (key/pt/ct NULL); RED_CRYPTO_ERR_LEN if
 *       len < 16 or len % 16 != 0 (no ciphertext stealing — see header).
 * Assumes: ct has room for len bytes; pt and ct may be the SAME pointer
 *          (in-place supported) but must not partially overlap.
 * Effects: ct = XTS-AES-256(key, data_unit, pt).
 */
int red_xts256_encrypt(const uint8_t key[RED_XTS256_KEY_LEN],
                       uint64_t data_unit,
                       const uint8_t *pt, size_t len, uint8_t *ct);

/*
 * XTS-AES-256 decrypt one data unit.
 *
 * CEP: CEP-1 | Complete
 * Cost: O(len/16) AES decryptions; 256 B of key schedules on stack.
 * Fail: RED_CRYPTO_ERR_NULL / RED_CRYPTO_ERR_LEN (as encrypt).
 * Assumes: pt has room for len bytes; in-place supported; no partial
 *          overlap. NOTE: XTS is confidentiality-only — there is no tag;
 *          integrity is the RAM disk's block-table audit responsibility.
 */
int red_xts256_decrypt(const uint8_t key[RED_XTS256_KEY_LEN],
                       uint64_t data_unit,
                       const uint8_t *ct, size_t len, uint8_t *pt);

#ifdef __cplusplus
}
#endif
#endif /* RED_XTS_H */
