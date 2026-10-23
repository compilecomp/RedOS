/* RedOS crypto core — BLAKE2b (RFC 7693), the hash substrate of the KMS.
 *
 * CEP: CEP-1 | Complete
 * Cost: one-shot over <= 4 GiB inputs; 128-byte blocks; fixed 12 rounds.
 * Fail: functions here cannot fail (validation is in red_blake2b()).
 * Assumes: no libc (all helpers local); out_len in [1,64]; key_len in
 *          [0,64]; little/big-endian irrelevant (byte-oriented, LE loads
 *          are explicit).
 *
 * Role in RedOS: Argon2id (RFC 9106) is built directly on this file
 * (H^x and the G compression function), and the KMS uses keyed BLAKE2b
 * as the lease/domain key-derivation PRF. A break here is a break of
 * every KMS guarantee — the KATs in tests/crypto/test_vectors.c pin
 * the exact RFC 7693 behavior (empty, "abc", block boundaries, keyed).
 *
 * Side-channel note (explicit, tracked): BLAKE2b is constant-time by
 * construction — the message schedule SIGMA and the IV are input-
 * independent, so every memory access pattern is fixed. No table
 * lookup depends on secret data.
 */
#ifndef RED_BLAKE2B_H
#define RED_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RED_BLAKE2B_OUT_MAX 64u /* maximum digest length (RFC 7693)  */
#define RED_BLAKE2B_KEY_MAX 64u /* maximum key length (RFC 7693)     */
#define RED_BLAKE2B_BLOCK   128u/* compression block size in bytes   */

/* Incremental BLAKE2b state (single-threaded use; ~200 B). */
typedef struct {
        uint64_t h[8];
        uint64_t t_lo, t_hi;    /* 128-bit byte counter */
        uint8_t  buf[RED_BLAKE2B_BLOCK];
        size_t   buflen;
        size_t   out_len;
} red_blake2b_st;

/*
 * Initialize an incremental BLAKE2b state.
 * CEP: CEP-1 | Complete
 * Cost: O(1) (~200 B of state); no alloc.
 * Fail: RED_CRYPTO_ERR_NULL (st NULL); RED_CRYPTO_ERR_LEN if out_len==0,
 *       out_len>64, or key_len>64 (or key NULL with key_len>0).
 * Assumes: st is writable; key readable for key_len bytes.
 */
int red_blake2b_init(red_blake2b_st *st, size_t out_len,
                     const void *key, size_t key_len);

/*
 * Feed input bytes (any length, any number of calls).
 * CEP: CEP-1 | Complete
 * Cost: O(in_len) compressions as full blocks accumulate.
 * Fail: RED_CRYPTO_ERR_NULL (st NULL, or in NULL with in_len>0).
 * Assumes: st was initialized (and not finalized); in readable.
 */
int red_blake2b_update(red_blake2b_st *st, const void *in, size_t in_len);

/*
 * Finalize: produce out_len bytes (the init-time out_len) into out.
 * CEP: CEP-1 | Complete
 * Cost: one compression (always — including the empty-input case).
 * Fail: RED_CRYPTO_ERR_NULL (st or out NULL).
 * Assumes: out has room for the init-time out_len bytes; st must be
 *          re-initialized before reuse (final is terminal).
 */
int red_blake2b_final(red_blake2b_st *st, void *out);

/*
 * One-shot BLAKE2b hash / keyed MAC (RFC 7693 section 3).
 * CEP: CEP-1 | Complete
 * Cost: O(in_len / 128) compressions; no alloc, no locks.
 * Fail: RED_CRYPTO_ERR_NULL if out is NULL, or in is NULL with in_len>0,
 *       or key is NULL with key_len>0;
 *       RED_CRYPTO_ERR_LEN if out_len==0, out_len>64, or key_len>64.
 *       (lengths validated before any pointer is dereferenced)
 * Assumes: out has room for out_len bytes; in readable for in_len bytes;
 *          key readable for key_len bytes.
 * Effects: out = BLAKE2b-`out_len`(in, key=key).
 */
int red_blake2b(void *out, size_t out_len,
                const void *in, size_t in_len,
                const void *key, size_t key_len);

#ifdef __cplusplus
}
#endif
#endif /* RED_BLAKE2B_H */
