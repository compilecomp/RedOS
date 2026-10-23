/* RedOS crypto core — BLAKE2b (RFC 7693) implementation.
 *
 * CEP: CEP-1 | Complete
 * Cost: 12 rounds per 128-byte block; incremental and one-shot share the
 *       same compression core (one source of truth, Law 3).
 * Fail: cannot fail beyond the contracts in red/blake2b.h.
 * Assumes: no libc; explicit LE loads (freestanding, alignment-safe).
 */
#include "red/blake2b.h"
#include "red/crypto.h"

/* IV (same as SHA-512 IV, RFC 7693 section 3.3). */
static const uint64_t IV[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* Message schedule sigma: 10 rounds; rounds 10..11 repeat rows 0..1. */
static const uint8_t SIGMA[12][16] = {
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
};

/* Explicit little-endian 64-bit load/store (freestanding, alignment-safe). */
static uint64_t le64(const uint8_t *p)
{
        return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
               ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
               ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
               ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void store64(uint8_t *p, uint64_t v)
{
        p[0] = (uint8_t)(v);        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);  p[3] = (uint8_t)(v >> 24);
        p[4] = (uint8_t)(v >> 32);  p[5] = (uint8_t)(v >> 40);
        p[6] = (uint8_t)(v >> 48);  p[7] = (uint8_t)(v >> 56);
}

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* RFC 7693 G: mixing of v[a],v[b],v[c],v[d] with message words mx,my. */
static void g_mix(uint64_t v[16], int a, int b, int c, int d, uint64_t mx,
                  uint64_t my)
{
        v[a] = v[a] + v[b] + mx;
        v[d] = ROTR(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = ROTR(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + my;
        v[d] = ROTR(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = ROTR(v[b] ^ v[c], 63);
}

/* One compression: h ^= F(h, block, t, last). */
static void compress(uint64_t h[8], const uint8_t block[128],
                     uint64_t t_lo, uint64_t t_hi, int last)
{
        uint64_t v[16];
        uint64_t m[16];
        int i;

        for (i = 0; i < 16; i++) {
                m[i] = le64(block + 8 * i);
        }
        for (i = 0; i < 8; i++) {
                v[i] = h[i];
                v[8 + i] = IV[i];
        }
        v[12] ^= t_lo;
        v[13] ^= t_hi;
        if (last) {
                v[14] ^= ~(uint64_t)0;
        }

        for (i = 0; i < 12; i++) {
                const uint8_t *s = SIGMA[i];
                g_mix(v, 0, 4, 8, 12, m[s[0]],  m[s[1]]);
                g_mix(v, 1, 5, 9, 13, m[s[2]],  m[s[3]]);
                g_mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                g_mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                g_mix(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
                g_mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                g_mix(v, 2, 7, 8, 13, m[s[12]],  m[s[13]]);
                g_mix(v, 3, 4, 9, 14, m[s[14]],  m[s[15]]);
        }

        for (i = 0; i < 8; i++) {
                h[i] ^= v[i] ^ v[8 + i];
        }
}

/* --- Incremental API ------------------------------------------------------ */

int red_blake2b_init(red_blake2b_st *st, size_t out_len,
                     const void *key, size_t key_len)
{
        size_t i;
        const uint8_t *kp = (const uint8_t *)key;

        if (st == NULL || (key == NULL && key_len > 0)) {
                return RED_CRYPTO_ERR_NULL;
        }
        if (out_len == 0 || out_len > RED_BLAKE2B_OUT_MAX ||
            key_len > RED_BLAKE2B_KEY_MAX) {
                return RED_CRYPTO_ERR_LEN;
        }

        for (i = 0; i < 8; i++) {
                st->h[i] = IV[i];
        }
        /* Parameter block 0: fanout=0, depth=1 (one-shot / leaf hashing). */
        st->h[0] ^= 0x01010000ULL ^ ((uint64_t)key_len << 8) ^
                    (uint64_t)out_len;
        st->t_lo = 0;
        st->t_hi = 0;
        st->buflen = 0;
        st->out_len = out_len;

        if (key_len > 0) {
                /* The padded key is the first 128-byte block of the stream;
                 * it is staged (not compressed) exactly like buffered data. */
                for (i = 0; i < RED_BLAKE2B_BLOCK; i++) {
                        st->buf[i] = 0;
                }
                for (i = 0; i < key_len; i++) {
                        st->buf[i] = kp[i];
                }
                st->buflen = RED_BLAKE2B_BLOCK;
        }
        return RED_CRYPTO_OK;
}

int red_blake2b_update(red_blake2b_st *st, const void *in, size_t in_len)
{
        const uint8_t *p = (const uint8_t *)in;

        if (st == NULL || (in == NULL && in_len > 0)) {
                return RED_CRYPTO_ERR_NULL;
        }

        while (in_len > 0) {
                size_t take;
                if (st->buflen == RED_BLAKE2B_BLOCK) {
                        /* Buffer is full and more data follows: this is a
                         * non-final block — flush it. */
                        st->t_lo += 128;
                        if (st->t_lo < 128) {
                                st->t_hi++;
                        }
                        compress(st->h, st->buf, st->t_lo, st->t_hi, 0);
                        st->buflen = 0;
                }
                take = RED_BLAKE2B_BLOCK - st->buflen;
                if (take > in_len) {
                        take = in_len;
                }
                for (size_t i = 0; i < take; i++) {
                        st->buf[st->buflen + i] = p[i];
                }
                st->buflen += take;
                p += take;
                in_len -= take;
        }
        return RED_CRYPTO_OK;
}

int red_blake2b_final(red_blake2b_st *st, void *out)
{
        uint8_t tmp[RED_BLAKE2B_OUT_MAX];
        uint8_t *o = (uint8_t *)out;
        size_t i;

        if (st == NULL || out == NULL) {
                return RED_CRYPTO_ERR_NULL;
        }

        /* The final block is ALWAYS compressed — including for the empty
         * unkeyed message (zero block, t=0, last flag), which is what
         * yields the canonical empty digest. */
        if (st->buflen < RED_BLAKE2B_BLOCK) {
                for (i = st->buflen; i < RED_BLAKE2B_BLOCK; i++) {
                        st->buf[i] = 0;
                }
        }
        st->t_lo += st->buflen;
        if (st->t_lo < st->buflen) {
                st->t_hi++;
        }
        compress(st->h, st->buf, st->t_lo, st->t_hi, 1);

        for (i = 0; i < 8; i++) {
                store64(tmp + 8 * i, st->h[i]);
        }
        for (i = 0; i < st->out_len; i++) {
                o[i] = tmp[i];
        }
        /* Hygiene: the state is terminal after final(); scrub the buffer. */
        for (i = 0; i < RED_BLAKE2B_BLOCK; i++) {
                st->buf[i] = 0;
        }
        st->buflen = 0;
        return RED_CRYPTO_OK;
}

/* --- One-shot wrapper ------------------------------------------------------ */

int red_blake2b(void *out, size_t out_len,
                const void *in, size_t in_len,
                const void *key, size_t key_len)
{
        red_blake2b_st st;
        int rc;

        if (out == NULL || (in == NULL && in_len > 0) ||
            (key == NULL && key_len > 0)) {
                return RED_CRYPTO_ERR_NULL;
        }
        if (out_len == 0 || out_len > RED_BLAKE2B_OUT_MAX ||
            key_len > RED_BLAKE2B_KEY_MAX) {
                return RED_CRYPTO_ERR_LEN;
        }

        rc = red_blake2b_init(&st, out_len, key, key_len);
        if (rc != RED_CRYPTO_OK) {
                return rc;
        }
        if (in_len > 0) {
                rc = red_blake2b_update(&st, in, in_len);
                if (rc != RED_CRYPTO_OK) {
                        return rc;
                }
        }
        return red_blake2b_final(&st, out);
}
