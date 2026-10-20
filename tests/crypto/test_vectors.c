/* RedOS crypto core — NIST GCM test vectors (host build).
 *
 * Source of truth: McGrew & Viega, "The Galois/Counter Mode of Operation",
 * revised spec (2005), Appendix B, Test Cases 13-16 (AES-256). Values were
 * cross-verified against an independent implementation before being pinned
 * here (CEP&CC Law 3: invariants enforced by test, not by comment).
 *
 * Additionally verifies the AES S-box table independently by recomputing it
 * from GF(2^8) inversion + the FIPS-197 affine transform, and exercises the
 * fail-closed decrypt path (tamper detection, buffer zeroing).
 *
 * CEP: CEP-2 | Complete (host-only tooling; libc allowed here)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "red/crypto.h"

static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t cap)
{
        size_t n = strlen(hex);
        size_t bytes = 0;

        if (n % 2 != 0) {
                fprintf(stderr, "internal: odd hex length\n");
                exit(2);
        }
        for (size_t i = 0; i < n; i += 2) {
                unsigned v;
                if (sscanf(hex + i, "%2x", &v) != 1) {
                        fprintf(stderr, "internal: bad hex\n");
                        exit(2);
                }
                if (bytes >= cap) {
                        fprintf(stderr, "internal: hex exceeds cap\n");
                        exit(2);
                }
                out[bytes++] = (uint8_t)v;
        }
        return bytes;
}

static int failures = 0;

static void check(int cond, const char *name)
{
        printf("%-52s %s\n", name, cond ? "PASS" : "FAIL");
        if (!cond) {
                failures++;
        }
}

/* --- Independent S-box recomputation (Law 3 enforcement) ---------------- */

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
        uint8_t p = 0;

        while (b != 0) {
                if (b & 1) {
                        p ^= a;
                }
                a = (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
                b >>= 1;
        }
        return p;
}

static uint8_t gf_pow(uint8_t a, unsigned e)
{
        uint8_t r = 1;

        while (e) {
                if (e & 1) {
                        r = gf_mul(r, a);
                }
                a = gf_mul(a, a);
                e >>= 1;
        }
        return r;
}

static uint8_t rotl8(uint8_t x, unsigned n)
{
        return (uint8_t)((x << n) | (x >> (8 - n)));
}

static void test_sbox_independent(void)
{
        int ok = 1;

        for (unsigned v = 0; v < 256; v++) {
                uint8_t inv = (v == 0) ? 0 : gf_pow((uint8_t)v, 254);
                uint8_t s = (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^
                                      rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
                if (s != red_aes256_sbox[v]) {
                        ok = 0;
                        break;
                }
        }
        check(ok, "S-box matches GF(2^8) inversion + affine");
}

/* --- GCM encrypt/decrypt against pinned NIST vectors -------------------- */

struct gcm_case {
        const char *name;
        const char *key;
        const char *iv;
        const char *pt;
        const char *aad;
        const char *ct;
        const char *tag;
};

static const struct gcm_case cases[] = {
        { "NIST GCM TC13 (empty)", "0000000000000000000000000000000000000000000000000000000000000000",
          "000000000000000000000000", "", "",
          "", "530f8afbc74536b9a963b4f1c4cb738b" },
        { "NIST GCM TC14 (1 block)", "0000000000000000000000000000000000000000000000000000000000000000",
          "000000000000000000000000", "00000000000000000000000000000000", "",
          "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919" },
        { "NIST GCM TC15 (60 B, no AAD)", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
          "cafebabefacedbaddecaf888",
          "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
          "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "",
          "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
          "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
          "b094dac5d93471bdec1a502270e3cc6c" },
        { "NIST GCM TC16 (56 B + 20 B AAD)", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
          "cafebabefacedbaddecaf888",
          "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
          "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
          "feedfacedeadbeeffeedfacedeadbeefabaddad2",
          "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
          "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
          "76fc6ece0f4e1768cddf8853bb2d551b" },
};

#define MAXBUF 128

/* FIPS-197 C.3 AES-256 known answer: zero key, zero block. */
static void test_aes256_ecb_kat(void)
{
        red_aes256_ctx ctx;
        const uint8_t zeros[16] = { 0 };
        const uint8_t zero_key[RED_CRYPTO_KEY_LEN] = { 0 };
        const uint8_t expect[16] = {
                0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
                0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
        };
        uint8_t out[16];

        check(red_aes256_init(&ctx, zero_key) == RED_CRYPTO_OK, "init(zero key) OK");
        red_aes256_encrypt_block(&ctx, zeros, out);
        check(memcmp(out, expect, 16) == 0, "FIPS-197 C.3 AES-256 ECB KAT");
        check(red_aes256_init(NULL, zero_key) == RED_CRYPTO_ERR_NULL,
              "init(NULL ctx) -> ERR_NULL");
        check(red_aes256_init(&ctx, NULL) == RED_CRYPTO_ERR_NULL,
              "init(NULL key) -> ERR_NULL");
}

static void run_case(const struct gcm_case *c)
{
        uint8_t key[32], iv[12], pt[MAXBUF], aad[MAXBUF], ct[MAXBUF], tag[16];
        uint8_t ct_out[MAXBUF], tag_out[16], pt_out[MAXBUF];
        size_t pt_len, aad_len, ct_len;
        int rc;

        hex_to_bytes(c->key, key, sizeof(key));
        hex_to_bytes(c->iv, iv, sizeof(iv));
        pt_len   = hex_to_bytes(c->pt, pt, sizeof(pt));
        aad_len  = hex_to_bytes(c->aad, aad, sizeof(aad));
        ct_len   = hex_to_bytes(c->ct, ct, sizeof(ct));
        hex_to_bytes(c->tag, tag, sizeof(tag));

        rc = red_aes256_gcm_encrypt(key, iv, pt, pt_len, aad, aad_len,
                                    ct_out, tag_out);
        check(rc == RED_CRYPTO_OK && ct_len == pt_len &&
              memcmp(ct_out, ct, ct_len) == 0 &&
              memcmp(tag_out, tag, 16) == 0, c->name);

        rc = red_aes256_gcm_decrypt(key, iv, ct, ct_len, aad, aad_len, tag,
                                    pt_out);
        check(rc == RED_CRYPTO_OK && memcmp(pt_out, pt, pt_len) == 0,
              "decrypt round-trip");
}

/* --- Fail-closed behavior ------------------------------------------------ */

static void test_tamper(void)
{
        uint8_t key[32], iv[12], pt[64], ct[64], tag[16], pt_out[64];
        size_t pt_len = 60;
        int rc;

        memset(key, 0x11, sizeof(key));
        memset(iv, 0x22, sizeof(iv));
        memset(pt, 0x33, sizeof(pt));

        rc = red_aes256_gcm_encrypt(key, iv, pt, pt_len, NULL, 0, ct, tag);
        check(rc == RED_CRYPTO_OK, "encrypt for tamper test");

        /* Flip one bit of the tag: decrypt must fail and zero the buffer. */
        tag[3] ^= 0x10;
        memset(pt_out, 0xAA, sizeof(pt_out));
        rc = red_aes256_gcm_decrypt(key, iv, ct, pt_len, NULL, 0, tag, pt_out);
        check(rc == RED_CRYPTO_ERR_AUTH, "tampered tag -> AUTH error");
        {
                int zeroed = 1;
                for (size_t i = 0; i < pt_len; i++) {
                        if (pt_out[i] != 0) { zeroed = 0; break; }
                }
                check(zeroed, "plaintext buffer zeroed on auth failure");
        }

        /* Flip one bit of ciphertext: same fail-closed contract. */
        rc = red_aes256_gcm_encrypt(key, iv, pt, pt_len, NULL, 0, ct, tag);
        check(rc == RED_CRYPTO_OK, "re-encrypt for ct tamper test");
        ct[7] ^= 0x01;
        memset(pt_out, 0xAA, sizeof(pt_out));
        rc = red_aes256_gcm_decrypt(key, iv, ct, pt_len, NULL, 0, tag, pt_out);
        check(rc == RED_CRYPTO_ERR_AUTH, "tampered ciphertext -> AUTH error");
        {
                int zeroed = 1;
                for (size_t i = 0; i < pt_len; i++) {
                        if (pt_out[i] != 0) { zeroed = 0; break; }
                }
                check(zeroed, "buffer zeroed on ct-tamper auth failure");
        }

        /* NULL contract enforcement. */
        rc = red_aes256_gcm_encrypt(NULL, iv, pt, pt_len, NULL, 0, ct, tag);
        check(rc == RED_CRYPTO_ERR_NULL, "NULL key rejected");
        rc = red_aes256_gcm_encrypt(key, NULL, pt, pt_len, NULL, 0, ct, tag);
        check(rc == RED_CRYPTO_ERR_NULL, "NULL IV rejected");
        rc = red_aes256_gcm_encrypt(key, iv, pt, pt_len, NULL, 0, ct, NULL);
        check(rc == RED_CRYPTO_ERR_NULL, "encrypt NULL tag rejected");
        rc = red_aes256_gcm_decrypt(key, iv, ct, pt_len, NULL, 0, NULL, pt_out);
        check(rc == RED_CRYPTO_ERR_NULL, "decrypt NULL tag rejected");
}

/* --- Aliasing + length contracts ----------------------------------------- */

static void test_aliasing_and_len(void)
{
        uint8_t key[32], iv[12], buf[64], buf2[64], tag[16];
        size_t len = 60;
        int rc;

        memset(key, 0x44, sizeof(key));
        memset(iv, 0x55, sizeof(iv));
        memset(buf, 0x66, sizeof(buf));
        memcpy(buf2, buf, sizeof(buf));

        /* Exact in-place (pt == ct) is supported and must round-trip. */
        rc = red_aes256_gcm_encrypt(key, iv, buf, len, NULL, 0, buf, tag);
        check(rc == RED_CRYPTO_OK, "in-place encrypt allowed");
        rc = red_aes256_gcm_decrypt(key, iv, buf, len, NULL, 0, tag, buf);
        check(rc == RED_CRYPTO_OK && memcmp(buf, buf2, len) == 0,
              "in-place decrypt round-trip");

        /* Partial overlap must be rejected without corrupting anything. */
        rc = red_aes256_gcm_encrypt(key, iv, buf, len, NULL, 0, buf + 8, tag);
        check(rc == RED_CRYPTO_ERR_LEN, "partial overlap encrypt rejected");
        rc = red_aes256_gcm_decrypt(key, iv, buf + 8, len, NULL, 0, tag, buf);
        check(rc == RED_CRYPTO_ERR_LEN, "partial overlap decrypt rejected");

        /* Length cap (SP 800-38D): value check fires before any dereference,
         * so data may be NULL here. */
        rc = red_aes256_gcm_encrypt(key, iv, NULL, (size_t)RED_CRYPTO_MAX_DATA + 1,
                                    NULL, 0, NULL, tag);
        check(rc == RED_CRYPTO_ERR_LEN, "oversize length rejected");
}

int main(void)
{
        test_aes256_ecb_kat();
        test_sbox_independent();
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                run_case(&cases[i]);
        }
        test_tamper();
        test_aliasing_and_len();

        if (failures != 0) {
                printf("\n%d FAILURE(S)\n", failures);
                return 1;
        }
        printf("\nALL CRYPTO TESTS PASSED\n");
        return 0;
}
