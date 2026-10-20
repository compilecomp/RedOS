/* RedOS crypto core — AES-256 block cipher (FIPS-197).
 *
 * CEP: CEP-1 | Complete
 * Cost: encrypt_block is fixed-work (14 rounds); S-box is a 256 B table.
 * Fail: functions here cannot fail.
 * Assumes: little/big-endian irrelevant (byte-oriented); no unaligned access
 *          beyond uint8_t; no libc (all helpers are local loops).
 *
 * Side-channel note (explicit, tracked): table-lookup S-box is NOT hardened
 * against cache-timing adversaries. Acceptable for Phase 1 (QEMU, local
 * attacker model). Hardening (bitsliced or CLMUL-based) is scheduled with the
 * Phase 2 kernel hardening pass and will be re-classed CEP-0 with evidence.
 */
#include "red/crypto.h"

const uint8_t red_aes256_sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static void red_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
        for (size_t i = 0; i < n; i++) {
                dst[i] = src[i];
        }
}

/* Rcon for AES-256: 7 values (words 8..56 at Nk boundaries). */
static const uint8_t red_rcon[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };

int red_aes256_init(red_aes256_ctx *ctx, const uint8_t key[RED_CRYPTO_KEY_LEN])
{
        uint8_t *rk;
        size_t i;

        if (ctx == 0 || key == 0) {
                return RED_CRYPTO_ERR_NULL;
        }

        rk = ctx->roundkeys;
        red_copy(rk, key, 32);

        /* Expand words 8..59 (bytes 32..239). Word w occupies bytes 4w..4w+3. */
        for (i = 32; i < 240; i += 4) {
                uint8_t t0 = rk[i - 4], t1 = rk[i - 3], t2 = rk[i - 2], t3 = rk[i - 1];

                if (i % 32 == 0) {
                        /* RotWord + SubWord + Rcon (i/32 - 1 indexes 0x01..0x40). */
                        uint8_t first = t0;
                        t0 = (uint8_t)(red_aes256_sbox[t1] ^ red_rcon[i / 32 - 1]);
                        t1 = red_aes256_sbox[t2];
                        t2 = red_aes256_sbox[t3];
                        t3 = red_aes256_sbox[first];
                } else if (i % 32 == 16) {
                        /* SubWord only (AES-256 extra nonlinearity point). */
                        t0 = red_aes256_sbox[t0];
                        t1 = red_aes256_sbox[t1];
                        t2 = red_aes256_sbox[t2];
                        t3 = red_aes256_sbox[t3];
                }

                rk[i]     = (uint8_t)(rk[i - 32] ^ t0);
                rk[i + 1] = (uint8_t)(rk[i - 31] ^ t1);
                rk[i + 2] = (uint8_t)(rk[i - 30] ^ t2);
                rk[i + 3] = (uint8_t)(rk[i - 29] ^ t3);
        }

        return RED_CRYPTO_OK;
}

static uint8_t red_xtime(uint8_t x)
{
        return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void red_add_round_key(uint8_t st[16], const uint8_t *rk)
{
        for (int i = 0; i < 16; i++) {
                st[i] ^= rk[i];
        }
}

static void red_sub_bytes(uint8_t st[16])
{
        for (int i = 0; i < 16; i++) {
                st[i] = red_aes256_sbox[st[i]];
        }
}

static void red_shift_rows(uint8_t st[16])
{
        uint8_t t;

        /* Row 1: rotate left 1. */
        t = st[1];  st[1]  = st[5];  st[5]  = st[9];  st[9]  = st[13]; st[13] = t;
        /* Row 2: rotate left 2. */
        t = st[2];  st[2]  = st[10]; st[10] = t;
        t = st[6];  st[6]  = st[14]; st[14] = t;
        /* Row 3: rotate left 3. */
        t = st[3];  st[3]  = st[15]; st[15] = st[11]; st[11] = st[7];  st[7]  = t;
}

static void red_mix_columns(uint8_t st[16])
{
        for (int c = 0; c < 4; c++) {
                uint8_t *p = st + 4 * c;
                uint8_t a = p[0], b = p[1], d = p[2], e = p[3];

                p[0] = (uint8_t)(red_xtime(a) ^ red_xtime(b) ^ b ^ d ^ e);
                p[1] = (uint8_t)(a ^ red_xtime(b) ^ red_xtime(d) ^ d ^ e);
                p[2] = (uint8_t)(a ^ b ^ red_xtime(d) ^ red_xtime(e) ^ e);
                p[3] = (uint8_t)(a ^ b ^ d ^ red_xtime(e) ^ red_xtime(a));
        }
}

void red_aes256_encrypt_block(const red_aes256_ctx *ctx,
                              const uint8_t in[RED_CRYPTO_BLOCK_LEN],
                              uint8_t out[RED_CRYPTO_BLOCK_LEN])
{
        uint8_t st[16];
        const uint8_t *rk = ctx->roundkeys;

        red_copy(st, in, 16);
        red_add_round_key(st, rk);

        for (int r = 1; r < 14; r++) {
                red_sub_bytes(st);
                red_shift_rows(st);
                red_mix_columns(st);
                red_add_round_key(st, rk + 16 * r);
        }

        red_sub_bytes(st);
        red_shift_rows(st);
        red_add_round_key(st, rk + 224);
        red_copy(out, st, 16);
}
