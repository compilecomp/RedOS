/* RedOS crypto core — cryptographic test vectors (host build).
 *
 * Source of truth, by primitive:
 *   AES-256 / GCM : McGrew & Viega spec (2005) Appendix B, Test Cases
 *                   13-16 (AES-256), cross-verified against an independent
 *                   implementation before being pinned (CEP&CC Law 3).
 *   BLAKE2b       : RFC 7693 behavior pinned via the reference digest set
 *                   (empty, "abc", 128/129-byte block boundaries, keyed
 *                   variants) generated with an independent implementation
 *                   and frozen here.
 *   Argon2id      : RFC 9106 section 5.3 official test vector, verbatim.
 *   XTS-AES-256   : IEEE 1619-2007 Annex B.2, 512-byte data unit #255
 *                   (e-digit/pi-digit key), as mirrored in the Linux
 *                   kernel test suite ("XTS-AES 10").
 *
 * Additionally verifies the AES S-box table independently by recomputing it
 * from GF(2^8) inversion + the FIPS-197 affine transform, exercises the
 * fail-closed decrypt path (tamper detection, buffer zeroing), and the
 * Argon2id/XTS contract rejections (named errors before any computation).
 *
 * CEP: CEP-2 | Complete (host-only tooling; libc allowed here)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "red/crypto.h"
#include "red/blake2b.h"
#include "red/argon2.h"
#include "red/xts.h"

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

/* --- BLAKE2b KATs (RFC 7693 behavior, pinned from reference digests) ----- */

static void expect_digest(const char *name, const uint8_t *got,
                          const char *hex, size_t n)
{
        uint8_t want[64];

        hex_to_bytes(hex, want, sizeof(want));
        check(memcmp(got, want, n) == 0, name);
}

static void test_blake2b_kat(void)
{
        uint8_t out[64];
        uint8_t in768[768];
        uint8_t in128[128];
        uint8_t in129[129];
        uint8_t key32[32];
        uint8_t key16[16];

        for (int i = 0; i < 768; i++) {
                in768[i] = (uint8_t)(i % 256);
        }
        for (int i = 0; i < 128; i++) {
                in128[i] = (uint8_t)i;
        }
        for (int i = 0; i < 129; i++) {
                in129[i] = (uint8_t)i;
        }
        for (int i = 0; i < 32; i++) {
                key32[i] = (uint8_t)i;
        }
        for (int i = 0; i < 16; i++) {
                key16[i] = (uint8_t)i;
        }

        check(red_blake2b(out, 64, "", 0, NULL, 0) == RED_CRYPTO_OK,
              "blake2b empty accepts");
        expect_digest("blake2b-512(empty) KAT", out,
                      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e"
                      "217f71f5419d25e1031afee585313896444934eb04b903a685b14"
                      "48b755d56f701afe9be2ce", 64);

        check(red_blake2b(out, 64, "abc", 3, NULL, 0) == RED_CRYPTO_OK,
              "blake2b abc accepts");
        expect_digest("blake2b-512(abc) KAT", out,
                      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12b"
                      "b6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8db"
                      "f1925ab92386edd4009923", 64);

        check(red_blake2b(out, 64, in768, 768, NULL, 0) == RED_CRYPTO_OK,
              "blake2b 768B accepts");
        expect_digest("blake2b-512(768B) KAT", out,
                      "323e97a7a859ee63c9013debb0ca995811e73117a2f574723416e"
                      "596ebc184e37a59b66d2f597df4a7c1b0d1d41a1a7f28774f46a6"
                      "864d56c57b9d6c5f7302fb", 64);

        check(red_blake2b(out, 32, "redos-lease-material", 20, key32, 32) ==
              RED_CRYPTO_OK, "blake2b keyed accepts");
        expect_digest("blake2b-256(keyed) KAT", out,
                      "15d1edea7cb699ae6ca2e84d97975a5eff4978f669a741b0ff160"
                      "57b5757f897", 32);

        check(red_blake2b(out, 64, in128, 128, NULL, 0) == RED_CRYPTO_OK,
              "blake2b 128B boundary accepts");
        expect_digest("blake2b-512(128B) KAT", out,
                      "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87ee"
                      "cbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f"
                      "10a039806c5dcc0da3d115", 64);
        /* ^ 2319...d115 = 128 hex chars exactly (guard against typos) */

        check(red_blake2b(out, 64, in129, 129, NULL, 0) == RED_CRYPTO_OK,
              "blake2b 129B boundary accepts");
        expect_digest("blake2b-512(129B) KAT", out,
                      "f59711d44a031d5f97a9413c065d1e614c417ede998590325f49b"
                      "ad2fd444d3e4418be19aec4e11449ac1a57207898bc57d76a1bcf3"
                      "566292c20c683a5c4648f", 64);

        check(red_blake2b(out, 64, "", 0, key16, 16) == RED_CRYPTO_OK,
              "blake2b keyed-empty accepts");
        expect_digest("blake2b-512(keyed,empty) KAT", out,
                      "be9ba4d16e01a2bcdfad4ae51984e0bb9fe88a5e34da8387ffd11"
                      "52bd0bbb7d9118bb368a6e6ddd8dd0adf46d58fcd368b744ca845"
                      "2c8c20d225eb3741f307bb", 64);
}

/* Incremental API must agree with the one-shot on chunked input. */
static void test_blake2b_incremental(void)
{
        uint8_t one[64], two[64];
        uint8_t in768[768];

        for (int i = 0; i < 768; i++) {
                in768[i] = (uint8_t)(i % 256);
        }
        check(red_blake2b(one, 64, in768, 768, NULL, 0) == RED_CRYPTO_OK,
              "blake2b incremental baseline");
        {
                red_blake2b_st st;
                check(red_blake2b_init(&st, 64, NULL, 0) == RED_CRYPTO_OK,
                      "blake2b incremental init");
                for (size_t off = 0; off < 768; off += 37) {
                        size_t take = 768 - off < 37 ? 768 - off : 37;
                        check(red_blake2b_update(&st, in768 + off, take) ==
                              RED_CRYPTO_OK, "blake2b incremental update");
                }
                check(red_blake2b_final(&st, two) == RED_CRYPTO_OK,
                      "blake2b incremental final");
        }
        check(memcmp(one, two, 64) == 0,
              "blake2b incremental == one-shot (odd chunks)");
}

/* --- Argon2id: RFC 9106 section 5.3 official vector ----------------------- */

static void test_argon2id_kat(void)
{
        uint8_t pwd[32], salt[16], secret[8], ad[12], tag[32];
        static uint8_t work[32 * 1024]; /* RFC vector: m=32 KiB */

        memset(pwd, 0x01, sizeof(pwd));
        memset(salt, 0x02, sizeof(salt));
        memset(secret, 0x03, sizeof(secret));
        memset(ad, 0x04, sizeof(ad));

        int rc = red_argon2id(tag, 32, pwd, 32, salt, 16, secret, 8, ad, 12,
                              3 /*passes*/, 32 /*KiB*/, 4 /*lanes*/,
                              work, sizeof(work));
        check(rc == RED_CRYPTO_OK, "argon2id RFC vector accepts");
        if (rc == RED_CRYPTO_OK) {
                expect_digest("argon2id RFC 9106 tag KAT", tag,
                              "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b6"
                              "5eb52520e96b01e659", 32);
        }
}

static void test_argon2id_contract(void)
{
        uint8_t pwd[8] = {1, 1, 1, 1, 1, 1, 1, 1};
        uint8_t salt[8] = {2, 2, 2, 2, 2, 2, 2, 2};
        uint8_t tag[32];
        static uint8_t work[32 * 1024];
        int rc;

        /* canary: rejections must leave the output buffer untouched */
        memset(tag, 0xAA, sizeof(tag));

        rc = red_argon2id(NULL, 32, pwd, 8, salt, 8, NULL, 0, NULL, 0,
                          1, 64, 1, work, sizeof(work));
        check(rc == RED_CRYPTO_ERR_NULL, "argon2id NULL tag rejected");

        rc = red_argon2id(tag, 3, pwd, 8, salt, 8, NULL, 0, NULL, 0,
                          1, 64, 1, work, sizeof(work));
        check(rc == RED_CRYPTO_ERR_LEN, "argon2id tag<4 rejected");

        rc = red_argon2id(tag, 32, pwd, 8, salt, 7, NULL, 0, NULL, 0,
                          1, 64, 1, work, sizeof(work));
        check(rc == RED_CRYPTO_ERR_LEN, "argon2id salt<8 rejected");

        rc = red_argon2id(tag, 32, pwd, 8, salt, 8, NULL, 0, NULL, 0,
                          0, 64, 1, work, sizeof(work));
        check(rc == RED_CRYPTO_ERR_LEN, "argon2id passes=0 rejected");

        rc = red_argon2id(tag, 32, pwd, 8, salt, 8, NULL, 0, NULL, 0,
                          1, 7, 1, work, sizeof(work));
        check(rc == RED_CRYPTO_ERR_LEN, "argon2id m<8p rejected");

        rc = red_argon2id(tag, 32, pwd, 8, salt, 8, NULL, 0, NULL, 0,
                          1, 64, 1, work, 1023);
        check(rc == RED_CRYPTO_ERR_LEN, "argon2id small work area rejected");

        /* no partial tag on contract breach: canary unchanged */
        {
                uint8_t canary[32];
                memset(canary, 0xAA, sizeof(canary));
                check(memcmp(tag, canary, 32) == 0,
                      "argon2id no partial tag on rejection");
        }
}

/* --- XTS-AES-256: IEEE 1619-2007 Annex B.2 512-byte data unit #255 --------- */

static void test_xts256_kat(void)
{
        static const uint8_t key[64] = {
                0x27,0x18,0x28,0x18,0x28,0x45,0x90,0x45,
                0x23,0x53,0x60,0x28,0x74,0x71,0x35,0x26,
                0x62,0x49,0x77,0x57,0x24,0x70,0x93,0x69,
                0x99,0x59,0x57,0x49,0x66,0x96,0x76,0x27,
                0x31,0x41,0x59,0x26,0x53,0x58,0x97,0x93,
                0x23,0x84,0x62,0x64,0x33,0x83,0x27,0x95,
                0x02,0x88,0x41,0x97,0x16,0x93,0x99,0x37,
                0x51,0x05,0x82,0x09,0x74,0x94,0x45,0x92
        };
        static uint8_t pt[512], ct[512], back[512];
        static const uint8_t want[16] = {
                0x1c,0x3b,0x3a,0x10,0x2f,0x77,0x03,0x86,
                0xe4,0x83,0x6c,0x99,0xe3,0x70,0xcf,0x9b
        };

        for (size_t i = 0; i < 512; i++) {
                pt[i] = (uint8_t)(i % 256);
        }
        check(red_xts256_encrypt(key, 255, pt, 512, ct) == RED_CRYPTO_OK,
              "xts256 IEEE vector encrypts");
        check(memcmp(ct, want, 16) == 0, "xts256 IEEE 1619 ct[0..16] KAT");
        check(red_xts256_decrypt(key, 255, ct, 512, back) == RED_CRYPTO_OK,
              "xts256 IEEE vector decrypts");
        check(memcmp(back, pt, 512) == 0, "xts256 round-trip 512B");
        /* wrong data unit must not decrypt to the original */
        check(red_xts256_decrypt(key, 254, ct, 512, back) == RED_CRYPTO_OK,
              "xts256 wrong-tweak decrypt accepts");
        check(memcmp(back, pt, 512) != 0,
              "xts256 wrong tweak yields different plaintext");

        /* in-place round-trip (exact aliasing supported) */
        memcpy(back, pt, 512);
        check(red_xts256_encrypt(key, 7, back, 512, back) == RED_CRYPTO_OK,
              "xts256 in-place encrypt accepts");
        check(red_xts256_decrypt(key, 7, back, 512, back) == RED_CRYPTO_OK,
              "xts256 in-place decrypt accepts");
        check(memcmp(back, pt, 512) == 0, "xts256 in-place round-trip");
}

static void test_xts256_contract(void)
{
        uint8_t key[64];
        uint8_t pt[48], ct[48];
        uint8_t overlap[64];
        int rc;

        memset(key, 0x11, sizeof(key));
        memset(pt, 0x22, sizeof(pt));
        memset(ct, 0xAA, sizeof(ct));

        rc = red_xts256_encrypt(NULL, 0, pt, 48, ct);
        check(rc == RED_CRYPTO_ERR_NULL, "xts256 NULL key rejected");

        rc = red_xts256_encrypt(key, 0, NULL, 48, ct);
        check(rc == RED_CRYPTO_ERR_NULL, "xts256 NULL pt rejected");

        rc = red_xts256_encrypt(key, 0, pt, 0, ct);
        check(rc == RED_CRYPTO_ERR_LEN, "xts256 len=0 rejected (min 16B)");

        rc = red_xts256_encrypt(key, 0, pt, 8, ct);
        check(rc == RED_CRYPTO_ERR_LEN, "xts256 len=8 rejected (min 16B)");

        rc = red_xts256_encrypt(key, 0, pt, 40, ct);
        check(rc == RED_CRYPTO_ERR_LEN, "xts256 non-multiple len rejected");

        /* partial overlap refused (same buffer, shifted output window) */
        memset(overlap, 0, sizeof(overlap));
        rc = red_xts256_encrypt(key, 0, overlap, 32, overlap + 16);
        check(rc == RED_CRYPTO_ERR_LEN, "xts256 partial overlap rejected");

        /* no ciphertext on rejection: canary unchanged */
        {
                uint8_t canary[48];
                memset(canary, 0xAA, sizeof(canary));
                check(memcmp(ct, canary, 48) == 0,
                      "xts256 no output on rejection");
        }
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
        test_blake2b_kat();
        test_blake2b_incremental();
        test_argon2id_kat();
        test_argon2id_contract();
        test_xts256_kat();
        test_xts256_contract();

        if (failures != 0) {
                printf("\n%d FAILURE(S)\n", failures);
                return 1;
        }
        printf("\nALL CRYPTO TESTS PASSED\n");
        return 0;
}
