/* RedOS crypto core — AES-256-GCM (NIST SP 800-38D).
 *
 * CEP: CEP-1 | Complete
 * Cost: encrypt/decrypt are O(len) over 16-byte blocks: one GHASH pass
 *       (gf128_mul is 128 iterations, no tables) + one CTR pass, two key
 *       schedules run sequentially. Peak stack <= 512 B per call.
 *       No heap, no locks, no syscalls, no libc.
 * Fail: see per-function contracts in red/crypto.h (all failure modes are
 *       enforced by tests/crypto/test_vectors.c).
 * Assumes: byte-addressable memory; 96-bit IV only (spec §8.2.1 default);
 *          caller buffers valid per header contract.
 *
 * Implementation notes (audit trail):
 *  - GHASH field: GF(2^128), polynomial R = 11100001 || 0^120 (0xe1 lead),
 *    bit-reflected convention per SP 800-38D; multiplication is table-less.
 *  - J0 = IV || 0^31 || 1 for 96-bit IVs; CTR starts at inc32(J0).
 *  - Decrypt verifies the tag (constant-time compare) BEFORE CTR-decrypting;
 *    on mismatch the plaintext buffer is zeroed (fail-closed).
 *  - Secret intermediates (round-key context, keystream, recomputed tag) are
 *    wiped before return. Residual risk (compiler may elide dead stores) is
 *    tracked as a Phase 2 hardening item with a Secure-Depends wipe review.
 */
#include "red/crypto.h"

static void red_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		dst[i] = src[i];
	}
}

static void red_zero(uint8_t *dst, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		dst[i] = 0u;
	}
}

static void red_xor16(uint8_t *dst, const uint8_t *src)
{
	for (int i = 0; i < 16; i++) {
		dst[i] ^= src[i];
	}
}

/* Z = X·H in GF(2^128), GCM bit convention. X is updated in place. */
static void red_ghash_mul(uint8_t x[16], const uint8_t h[16])
{
	uint8_t z[16];
	uint8_t v[16];

	red_zero(z, 16);
	red_copy(v, h, 16);

	for (int i = 0; i < 128; i++) {
		if ((x[i >> 3] >> (7 - (i & 7))) & 1u) {
			red_xor16(z, v);
		}
		uint8_t lsb = (uint8_t)(v[15] & 1u);
		for (int j = 15; j > 0; j--) {
			v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
		}
		v[0] >>= 1;
		if (lsb) {
			v[0] ^= 0xe1;
		}
	}

	red_copy(x, z, 16);
}

/* Absorb data into the GHASH accumulator (zero-pads the final block). */
static void red_ghash_update(uint8_t y[16], const uint8_t h[16],
                             const uint8_t *data, size_t len)
{
	uint8_t block[16];

	while (len > 0) {
		size_t take = (len < 16) ? len : 16;

		red_copy(block, data, take);
		if (take < 16) {
			red_zero(block + take, 16 - take);
		}
		red_xor16(y, block);
		red_ghash_mul(y, h);
		data += take;
		len -= take;
	}
}

static void red_inc32(uint8_t cb[16])
{
	for (int i = 15; i >= 12; i--) {
		cb[i] = (uint8_t)(cb[i] + 1u);
		if (cb[i] != 0) {
			break;
		}
	}
}

/* Constant-time tag comparison (no early exit). */
static int red_tag_equal(const uint8_t a[16], const uint8_t b[16])
{
	volatile uint8_t diff = 0;

	for (int i = 0; i < 16; i++) {
		diff |= (uint8_t)(a[i] ^ b[i]);
	}
	return diff == 0;
}

/* Length block: be64(aad_bits) || be64(data_bits). Callers bound inputs to
 * RED_CRYPTO_MAX_DATA, so the *8 products cannot overflow uint64_t. */
static void red_len_block(uint8_t lb[16], size_t aad_len, size_t data_len)
{
	uint64_t abits = (uint64_t)aad_len * 8u;
	uint64_t dbits = (uint64_t)data_len * 8u;

	red_zero(lb, 16);
	for (int i = 0; i < 8; i++) {
		lb[i]     = (uint8_t)(abits >> (56 - 8 * i));
		lb[8 + i] = (uint8_t)(dbits >> (56 - 8 * i));
	}
}

/*
 * Compute J0 from a 96-bit IV (SP 800-38D §7.1).
 * Fail: cannot fail. Assumes: j0 has 16 writable bytes.
 */
static void red_gcm_j0(const uint8_t iv[12], uint8_t j0[16])
{
	red_copy(j0, iv, 12);
	j0[12] = 0u;
	j0[13] = 0u;
	j0[14] = 0u;
	j0[15] = 1u;
}

/*
 * CEP: CEP-1 | Complete
 * Compute the GCM tag T over (aad, data) under key. tag_out = E(K,J0) xor GHASH.
 * Cost: O(aad_len + data_len); stack ~320 B; no alloc.
 * Fail: RED_CRYPTO_ERR_NULL on key==NULL or tag_out==NULL.
 * Assumes: iv readable for 12 bytes; tag_out has 16 writable bytes.
 * Zeroization: round-key context wiped before return.
 */
static int red_gcm_tag(const uint8_t key[32],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *data, size_t data_len,
                       const uint8_t iv[12], uint8_t tag_out[16])
{
	red_aes256_ctx ctx;
	const uint8_t zeros[16] = { 0 };
	uint8_t h[16], j0[16], y[16], lb[16], e_j0[16];
	int rc;

	if (key == 0 || tag_out == 0) {
		return RED_CRYPTO_ERR_NULL;
	}

	rc = red_aes256_init(&ctx, key);
	if (rc != RED_CRYPTO_OK) {
		return rc;
	}

	red_aes256_encrypt_block(&ctx, zeros, h);   /* H = E(K, 0^128) */
	red_gcm_j0(iv, j0);

	red_zero(y, 16);
	red_ghash_update(y, h, aad, aad_len);
	red_ghash_update(y, h, data, data_len);
	red_len_block(lb, aad_len, data_len);
	red_ghash_update(y, h, lb, 16);

	red_aes256_encrypt_block(&ctx, j0, e_j0);
	for (int i = 0; i < 16; i++) {
		tag_out[i] = (uint8_t)(e_j0[i] ^ y[i]);
	}

	red_zero((uint8_t *)ctx.roundkeys, sizeof(ctx.roundkeys));
	return RED_CRYPTO_OK;
}

/*
 * CEP: CEP-1 | Complete
 * CTR path (SP 800-38D §6.5): keystream from inc32(J0); out = in xor keystream.
 * Cost: O(len); stack ~300 B; no alloc.
 * Fail: RED_CRYPTO_ERR_NULL on key==NULL.
 * Assumes: in/out do not partially overlap (exact aliasing allowed);
 *          out has len writable bytes.
 * Zeroization: round-key context and last keystream block wiped before return.
 */
static int red_gcm_ctr(const uint8_t key[32], const uint8_t iv[12],
                       const uint8_t *in, size_t len, uint8_t *out)
{
	red_aes256_ctx ctx;
	uint8_t j0[16], cb[16], ks[16];
	size_t off = 0;
	int rc;

	rc = red_aes256_init(&ctx, key);
	if (rc != RED_CRYPTO_OK) {
		return rc;
	}
	red_gcm_j0(iv, j0);
	red_copy(cb, j0, 16);

	while (off < len) {
		size_t take;

		red_inc32(cb);
		red_aes256_encrypt_block(&ctx, cb, ks);

		take = (len - off < 16) ? (len - off) : 16;
		for (size_t i = 0; i < take; i++) {
			out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
		}
		off += take;
	}

	red_zero(ks, sizeof(ks));
	red_zero((uint8_t *)ctx.roundkeys, sizeof(ctx.roundkeys));
	return RED_CRYPTO_OK;
}

/*
 * Shared argument validation. Order is fixed and pointer-safe:
 *   1. key/iv/tag NULL        (no data deref needed)
 *   2. length cap             (no deref needed — value check only)
 *   3. data/out NULL with len>0
 *   4. aad NULL with aad_len>0
 *   5. partial in/out overlap (exact aliasing in==out is allowed and tested)
 * Returns RED_CRYPTO_OK or the first matching error.
 */
static int red_gcm_check_args(const uint8_t *key, const uint8_t *iv,
                              const uint8_t *tag,
                              const uint8_t *data, size_t data_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *out)
{
	if (key == 0 || iv == 0 || tag == 0) {
		return RED_CRYPTO_ERR_NULL;
	}
	if ((uint64_t)data_len > RED_CRYPTO_MAX_DATA ||
	    (uint64_t)aad_len > RED_CRYPTO_MAX_DATA) {
		return RED_CRYPTO_ERR_LEN;
	}
	if (data_len > 0 && (data == 0 || out == 0)) {
		return RED_CRYPTO_ERR_NULL;
	}
	if (aad_len > 0 && aad == 0) {
		return RED_CRYPTO_ERR_NULL;
	}
	if (data_len > 0 && data != out) {
		const uint8_t *d_lo = (data < out) ? data : out;
		const uint8_t *d_hi = (data < out) ? out : data;

		/* Partial overlap: ranges intersect but neither contains the
		 * other exactly (in==out already excluded above). */
		if (d_lo + data_len > d_hi) {
			return RED_CRYPTO_ERR_LEN;
		}
	}
	return RED_CRYPTO_OK;
}

int red_aes256_gcm_encrypt(const uint8_t key[RED_CRYPTO_KEY_LEN],
                           const uint8_t iv[RED_CRYPTO_IV_LEN],
                           const uint8_t *pt, size_t pt_len,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *ct, uint8_t tag[RED_CRYPTO_TAG_LEN])
{
	int rc = red_gcm_check_args(key, iv, tag, pt, pt_len, aad, aad_len, ct);

	if (rc != RED_CRYPTO_OK) {
		return rc;
	}

	rc = red_gcm_ctr(key, iv, pt, pt_len, ct);
	if (rc != RED_CRYPTO_OK) {
		return rc;
	}
	return red_gcm_tag(key, aad, aad_len, ct, pt_len, iv, tag);
}

int red_aes256_gcm_decrypt(const uint8_t key[RED_CRYPTO_KEY_LEN],
                           const uint8_t iv[RED_CRYPTO_IV_LEN],
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t tag[RED_CRYPTO_TAG_LEN],
                           uint8_t *pt)
{
	uint8_t computed[16];
	int rc;

	if (tag == 0) {
		return RED_CRYPTO_ERR_NULL;
	}
	rc = red_gcm_check_args(key, iv, tag, ct, ct_len, aad, aad_len, pt);
	if (rc != RED_CRYPTO_OK) {
		return rc;
	}

	/* Authenticate first: recompute tag over (aad, ct). Fail-closed. */
	rc = red_gcm_tag(key, aad, aad_len, ct, ct_len, iv, computed);
	if (rc != RED_CRYPTO_OK) {
		return rc;
	}
	if (!red_tag_equal(computed, tag)) {
		red_zero(computed, sizeof(computed));
		red_zero(pt, ct_len);
		return RED_CRYPTO_ERR_AUTH;
	}
	red_zero(computed, sizeof(computed));

	rc = red_gcm_ctr(key, iv, ct, ct_len, pt);
	return rc;
}
