/* RedOS crypto core — Argon2id (RFC 9106), the KMS key-derivation KDF.
 *
 * CEP: CEP-1 | Complete
 * Cost: O(passes * memory) block computations; memory-bounded by design
 *       (the caller supplies the work area — this core never allocates).
 * Fail: every contract breach returns a named error BEFORE any sensitive
 *       computation runs (fail-closed: no partial tag is ever written).
 * Assumes: little-endian arithmetic via explicit LE serialization; the
 *       work area is caller-owned writable memory of work_len bytes.
 *
 * Scope decision (documented, CEP&CC Law 7): this core implements
 * Argon2id ONLY — the RFC 9106 MUST-implement variant and the side-
 * channel-hardened one. Argon2d/Argon2i are deliberately not provided
 * (smaller TCB; the data-independent addressing path exists internally
 * because RFC 9106 defines Argon2id's first half-pass in terms of it).
 *
 * Version policy: only version 0x13 (current) is accepted.
 */
#ifndef RED_ARGON2_H
#define RED_ARGON2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version 0x13 (RFC 9106). Other versions are rejected, never improvised. */
#define RED_ARGON2_VERSION_13 0x13u

/* Parameter policy floors (RFC 9106 section 3.1 / reference impl):        */
#define RED_ARGON2_TAG_MIN   4u   /* tag length floor (RFC: T >= 4)       */
#define RED_ARGON2_TAG_MAX   1024u
#define RED_ARGON2_SALT_MIN  8u   /* reference-implementation floor       */
#define RED_ARGON2_PASS_MIN  1u
#define RED_ARGON2_LANE_MAX  (1u << 24)

/*
 * Argon2id (RFC 9106), one-shot.
 *
 * CEP: CEP-1 | Complete
 * Cost: passes * m' block computations (m' = 4*p*floor(m/(4*p))); each
 *       block is 1 KiB of the caller's work area. No allocation, no
 *       locks, no syscalls. Stack use is O(1) (two 1 KiB block buffers).
 * Fail: RED_CRYPTO_ERR_NULL if tag/pwd/salt/work is NULL (or an optional
 *       input is NULL with a non-zero length);
 *       RED_CRYPTO_ERR_LEN if tag_len out of [4,1024], salt_len < 8,
 *       passes == 0, lanes == 0 or > 2^24-1, m' > work capacity, or the
 *       m' < 8*lanes floor is violated;
 *       RED_CRYPTO_ERR_AUTH is NOT produced here (kept for ABI symmetry).
 *       (all parameter validation happens before any block is touched)
 * Assumes: work is writable for work_len bytes and (for kernel callers)
 *       belongs to a Locked-class frame region — the work area carries
 *       password-derived intermediate state and MUST be wiped by the
 *       caller afterwards (see kms.rs; the core wipes its block buffers
 *       before returning, but cannot wipe caller memory it does not own).
 * Effects: tag = Argon2id v0x13 output (RFC 9106 section 3.2).
 */
int red_argon2id(uint8_t *tag, uint32_t tag_len,
                 const void *pwd, uint32_t pwd_len,
                 const void *salt, uint32_t salt_len,
                 const void *secret, uint32_t secret_len,
                 const void *ad, uint32_t ad_len,
                 uint32_t passes, uint32_t memory_kib, uint32_t lanes,
                 void *work, uint32_t work_len);

#ifdef __cplusplus
}
#endif
#endif /* RED_ARGON2_H */
