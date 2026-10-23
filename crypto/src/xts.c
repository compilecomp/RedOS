/* RedOS crypto core — XTS-AES-256 implementation (SP 800-38E subset).
 *
 * CEP: CEP-1 | Complete
 * Cost: see red/xts.h (contract lives there).
 * Fail: cannot fail beyond the contract in red/xts.h.
 * Assumes: no libc; key schedules are scrubbed before return (the tweak
 *          key K2 decrypts every data unit if it leaked).
 */
#include "red/xts.h"
#include "red/crypto.h"

/* IEEE 1619 GF(2^128): the LEFTMOST bit of the block is the coefficient
 * of x^0 (mirror image of the GCM convention). Doubling by x therefore
 * shifts the byte array left through the MSB with 0x87 reduction at the
 * far end. */
static void gf_double(uint8_t t[RED_CRYPTO_BLOCK_LEN])
{
        uint8_t carry = (uint8_t)(t[0] >> 7);

        for (int i = 0; i < 15; i++) {
                t[i] = (uint8_t)((t[i] << 1) | (t[i + 1] >> 7));
        }
        t[15] = (uint8_t)((t[15] << 1) ^ (carry ? 0x87 : 0x00));
}

/* Validate and set up: returns 0 on success (schedules filled), else the
 * named error code. Shared by encrypt/decrypt (Law 3: one contract). */
static int xts_setup(const uint8_t key[RED_XTS256_KEY_LEN],
                     const uint8_t *in, const uint8_t *out, size_t len,
                     red_aes256_ctx *k1, red_aes256_ctx *k2)
{
        if (key == NULL || in == NULL || out == NULL) {
                return RED_CRYPTO_ERR_NULL;
        }
        if (len < RED_XTS256_UNIT_MIN || len % RED_CRYPTO_BLOCK_LEN != 0) {
                return RED_CRYPTO_ERR_LEN; /* SP 800-38E subset; see header */
        }
        if (in != out &&
            in < out + len && out < in + len) {
                return RED_CRYPTO_ERR_LEN; /* partial overlap refused */
        }
        if (red_aes256_init(k1, key) != RED_CRYPTO_OK ||
            red_aes256_init(k2, key + RED_CRYPTO_KEY_LEN) != RED_CRYPTO_OK) {
                return RED_CRYPTO_ERR_NULL; /* init cannot fail; defensive */
        }
        return RED_CRYPTO_OK;
}

int red_xts256_encrypt(const uint8_t key[RED_XTS256_KEY_LEN],
                       uint64_t data_unit,
                       const uint8_t *pt, size_t len, uint8_t *ct)
{
        red_aes256_ctx k1, k2;
        uint8_t tweak[RED_CRYPTO_BLOCK_LEN];
        uint8_t block[RED_CRYPTO_BLOCK_LEN];
        int rc = xts_setup(key, pt, ct, len, &k1, &k2);

        if (rc != RED_CRYPTO_OK) {
                return rc;
        }

        /* Tweak = data unit number as 128-bit LE (IEEE 1619). */
        for (int i = 0; i < 16; i++) {
                tweak[i] = 0;
        }
        for (int i = 0; i < 8; i++) {
                tweak[i] = (uint8_t)(data_unit >> (8 * i));
        }
        red_aes256_encrypt_block(&k2, tweak, tweak); /* PP = E_K2(T) */

        for (size_t off = 0; off < len; off += RED_CRYPTO_BLOCK_LEN) {
                for (int i = 0; i < 16; i++) {
                        block[i] = (uint8_t)(pt[off + i] ^ tweak[i]);
                }
                red_aes256_encrypt_block(&k1, block, block);
                for (int i = 0; i < 16; i++) {
                        ct[off + i] = (uint8_t)(block[i] ^ tweak[i]);
                }
                gf_double(tweak);
        }

        /* Hygiene: scrub both schedules and the last tweak. */
        for (int i = 0; i < 240; i++) {
                k1.roundkeys[i] = 0;
                k2.roundkeys[i] = 0;
        }
        for (int i = 0; i < 16; i++) {
                tweak[i] = 0;
                block[i] = 0;
        }
        return RED_CRYPTO_OK;
}

int red_xts256_decrypt(const uint8_t key[RED_XTS256_KEY_LEN],
                       uint64_t data_unit,
                       const uint8_t *ct, size_t len, uint8_t *pt)
{
        red_aes256_ctx k1, k2;
        uint8_t tweak[RED_CRYPTO_BLOCK_LEN];
        uint8_t block[RED_CRYPTO_BLOCK_LEN];
        int rc = xts_setup(key, ct, pt, len, &k1, &k2);

        if (rc != RED_CRYPTO_OK) {
                return rc;
        }

        for (int i = 0; i < 16; i++) {
                tweak[i] = 0;
        }
        for (int i = 0; i < 8; i++) {
                tweak[i] = (uint8_t)(data_unit >> (8 * i));
        }
        red_aes256_encrypt_block(&k2, tweak, tweak);

        for (size_t off = 0; off < len; off += RED_CRYPTO_BLOCK_LEN) {
                for (int i = 0; i < 16; i++) {
                        block[i] = (uint8_t)(ct[off + i] ^ tweak[i]);
                }
                red_aes256_decrypt_block(&k1, block, block);
                for (int i = 0; i < 16; i++) {
                        pt[off + i] = (uint8_t)(block[i] ^ tweak[i]);
                }
                gf_double(tweak);
        }

        for (int i = 0; i < 240; i++) {
                k1.roundkeys[i] = 0;
                k2.roundkeys[i] = 0;
        }
        for (int i = 0; i < 16; i++) {
                tweak[i] = 0;
                block[i] = 0;
        }
        return RED_CRYPTO_OK;
}
