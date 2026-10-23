/* RedOS crypto core — Argon2id (RFC 9106) implementation.
 *
 * CEP: CEP-1 | Complete
 * Cost: passes * m' block computations; see red/argon2.h for the contract.
 * Fail: cannot fail beyond the contract in red/argon2.h (validation is
 *       done there before this file is entered with usable parameters —
 *       in practice red_argon2id() validates then computes).
 * Assumes: little-endian 32/64-bit serialization is explicit (no host
 *          endianness dependence); single-threaded caller (the scratch
 *          blocks below are file-scope statics — the kernel is one CPU,
 *          cooperative, no interrupts; host tests are single-threaded).
 *
 * Threading note (CEP&CC Law 7 — cost where it is): RFC 9106 allows
 * lane-parallel filling; RedOS is a uniprocessor microkernel, so lanes
 * are filled sequentially in slice-major order (identical semantics to
 * the RFC's single-thread reference fill_memory_blocks_st).
 */
#include "red/argon2.h"
#include "red/blake2b.h"
#include "red/crypto.h"

#define SYNC_POINTS 4u          /* RFC 9106 section 3.4: four slices   */
#define ADDRESSES_IN_BLOCK 128u /* J1J2 pairs per address block        */
#define TYPE_ARGON2ID 2u        /* RFC 9106 section 3.1                */

typedef struct {
        uint64_t v[128]; /* 1024 bytes = 128 x uint64 */
} block_t;

/* Scratch blocks (see threading note above). Kernel stack budget makes
 * ~5 KiB of stack locals unacceptable; statics are safe in this design. */
static block_t SCRATCH_R; /* fill_block: R = ref ^ prev            */
static block_t SCRATCH_T; /* fill_block: Q/Z accumulator           */
static block_t ADDR_BLCK; /* data-independent address block        */
static block_t ADDR_INPT; /* address-block input (Z || counter...) */
static block_t ADDR_ZERO; /* all-zero block for G(ZERO, ...)       */

/* --- LE serialization helpers ---------------------------------------------- */

static void store32_le(uint8_t *p, uint32_t x)
{
        p[0] = (uint8_t)(x);
        p[1] = (uint8_t)(x >> 8);
        p[2] = (uint8_t)(x >> 16);
        p[3] = (uint8_t)(x >> 24);
}

/* --- H' (RFC 9106 section 3.3) ---------------------------------------------- */

/*
 * H'^T(A): if T <= 64, H^T(LE32(T) || A); else the 32-byte-truncated
 * chain V_1..V_r plus the final H^(T-32r)(V_r) — implemented with the
 * incremental BLAKE2b so no input copies are ever made.
 */
static void blake2b_long(void *out, uint32_t out_len, const void *in,
                         uint32_t in_len)
{
        uint8_t lenbuf[4];
        red_blake2b_st st;

        if (out_len <= RED_BLAKE2B_OUT_MAX) {
                (void)red_blake2b_init(&st, out_len, NULL, 0);
                store32_le(lenbuf, out_len);
                (void)red_blake2b_update(&st, lenbuf, 4);
                if (in_len > 0) {
                        (void)red_blake2b_update(&st, in, in_len);
                }
                (void)red_blake2b_final(&st, out);
                return;
        }

        {
                uint8_t v[RED_BLAKE2B_OUT_MAX];
                uint8_t *o = (uint8_t *)out;
                uint32_t produced = 32;
                uint32_t i;

                (void)red_blake2b_init(&st, 64, NULL, 0);
                store32_le(lenbuf, out_len);
                (void)red_blake2b_update(&st, lenbuf, 4);
                (void)red_blake2b_update(&st, in, in_len);
                (void)red_blake2b_final(&st, v);
                for (i = 0; i < 32; i++) {
                        o[i] = v[i];
                }

                while (out_len - produced > RED_BLAKE2B_OUT_MAX) {
                        /* V_i = H^64(V_{i-1}); emit first 32 bytes. */
                        (void)red_blake2b(v, 64, v, 64, NULL, 0);
                        for (i = 0; i < 32; i++) {
                                o[produced + i] = v[i];
                        }
                        produced += 32;
                }
                /* Final chunk: H^(out_len - produced)(V_r), <= 64 bytes. */
                (void)red_blake2b(o + produced, out_len - produced, v, 64,
                                  NULL, 0);
        }
}

/* --- H0 (RFC 9106 section 3.2, Figure 1) ------------------------------------ */

static void initial_hash(uint8_t h0[64], uint32_t tag_len, const void *pwd,
                         uint32_t pwd_len, const void *salt,
                         uint32_t salt_len, const void *secret,
                         uint32_t secret_len, const void *ad,
                         uint32_t ad_len, uint32_t passes,
                         uint32_t memory_kib, uint32_t lanes)
{
        uint8_t w[4];
        red_blake2b_st st;

        (void)red_blake2b_init(&st, 64, NULL, 0);
        store32_le(w, lanes);      (void)red_blake2b_update(&st, w, 4);
        store32_le(w, tag_len);    (void)red_blake2b_update(&st, w, 4);
        store32_le(w, memory_kib); (void)red_blake2b_update(&st, w, 4);
        store32_le(w, passes);     (void)red_blake2b_update(&st, w, 4);
        store32_le(w, RED_ARGON2_VERSION_13);
        (void)red_blake2b_update(&st, w, 4);
        store32_le(w, TYPE_ARGON2ID); (void)red_blake2b_update(&st, w, 4);

        store32_le(w, pwd_len);    (void)red_blake2b_update(&st, w, 4);
        (void)red_blake2b_update(&st, pwd, pwd_len);
        store32_le(w, salt_len);   (void)red_blake2b_update(&st, w, 4);
        (void)red_blake2b_update(&st, salt, salt_len);
        store32_le(w, secret_len); (void)red_blake2b_update(&st, w, 4);
        if (secret_len > 0) {
                (void)red_blake2b_update(&st, secret, secret_len);
        }
        store32_le(w, ad_len);     (void)red_blake2b_update(&st, w, 4);
        if (ad_len > 0) {
                (void)red_blake2b_update(&st, ad, ad_len);
        }
        (void)red_blake2b_final(&st, h0);
}

/* --- BLAKE2b round on 16 words (RFC 9106 section 3.6, Figure 19) ------------ */

/* GB: modular addition fused with 32x32->64 multiplication (mod 2^64).
 * Unsigned arithmetic: wrap is defined behavior (C11 6.2.5/9). */
#define GB(a, b, c, d)                                                      \
        do {                                                                \
                (a) = (a) + (b) +                                           \
                      2ULL * (uint64_t)(uint32_t)(a) * (uint32_t)(b);       \
                (d) = ROTR64((d) ^ (a), 32);                                \
                (c) = (c) + (d) +                                           \
                      2ULL * (uint64_t)(uint32_t)(c) * (uint32_t)(d);       \
                (b) = ROTR64((b) ^ (c), 24);                                \
                (a) = (a) + (b) +                                           \
                      2ULL * (uint64_t)(uint32_t)(a) * (uint32_t)(b);       \
                (d) = ROTR64((d) ^ (a), 16);                                \
                (c) = (c) + (d) +                                           \
                      2ULL * (uint64_t)(uint32_t)(c) * (uint32_t)(d);       \
                (b) = ROTR64((b) ^ (c), 63);                                \
        } while (0)

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

/* P: one BLAKE2b round over the 8x8 matrix of 16-byte registers
 * (row pass then column pass — RFC 9106 Figures 18/19). */
#define BLAKE2_ROUND_NOMSG(w0, w1, w2, w3, w4, w5, w6, w7,                   \
                           w8, w9, w10, w11, w12, w13, w14, w15)             \
        do {                                                                 \
                GB(w0, w4, w8, w12);                                         \
                GB(w1, w5, w9, w13);                                         \
                GB(w2, w6, w10, w14);                                        \
                GB(w3, w7, w11, w15);                                        \
                GB(w0, w5, w10, w15);                                        \
                GB(w1, w6, w11, w12);                                        \
                GB(w2, w7, w8, w13);                                         \
                GB(w3, w4, w9, w14);                                         \
        } while (0)

/* --- fill_block (RFC 9106 section 3.5, Figure 15/16) ------------------------ */

static void fill_block(const block_t *prev, const block_t *ref,
                       block_t *next, int with_xor)
{
        block_t *r = &SCRATCH_R;
        block_t *t = &SCRATCH_T;
        unsigned i;

        for (i = 0; i < 128; i++) {
                r->v[i] = ref->v[i] ^ prev->v[i];
                t->v[i] = r->v[i];
        }
        if (with_xor) {
                for (i = 0; i < 128; i++) {
                        t->v[i] ^= next->v[i];
                }
        }

        /* Row pass: rows of 16-byte registers (v[16i .. 16i+15]). */
        for (i = 0; i < 8; i++) {
                BLAKE2_ROUND_NOMSG(
                        r->v[16 * i],      r->v[16 * i + 1],
                        r->v[16 * i + 2],  r->v[16 * i + 3],
                        r->v[16 * i + 4],  r->v[16 * i + 5],
                        r->v[16 * i + 6],  r->v[16 * i + 7],
                        r->v[16 * i + 8],  r->v[16 * i + 9],
                        r->v[16 * i + 10], r->v[16 * i + 11],
                        r->v[16 * i + 12], r->v[16 * i + 13],
                        r->v[16 * i + 14], r->v[16 * i + 15]);
        }
        /* Column pass: columns of 16-byte registers. */
        for (i = 0; i < 8; i++) {
                BLAKE2_ROUND_NOMSG(
                        r->v[2 * i],       r->v[2 * i + 1],
                        r->v[2 * i + 16],  r->v[2 * i + 17],
                        r->v[2 * i + 32],  r->v[2 * i + 33],
                        r->v[2 * i + 48],  r->v[2 * i + 49],
                        r->v[2 * i + 64],  r->v[2 * i + 65],
                        r->v[2 * i + 80],  r->v[2 * i + 81],
                        r->v[2 * i + 96],  r->v[2 * i + 97],
                        r->v[2 * i + 112], r->v[2 * i + 113]);
        }

        for (i = 0; i < 128; i++) {
                next->v[i] = t->v[i] ^ r->v[i];
        }
}

/* --- Address generation (RFC 9106 section 3.4.1.2, Figure 11) ---------------- */

static void next_addresses(void)
{
        /* Z was staged in ADDR_INPT; the counter is word 6 (RFC: the
         * 64-byte Z is followed by LE64(i) at word offset 6). */
        ADDR_INPT.v[6]++;
        fill_block(&ADDR_ZERO, &ADDR_INPT, &ADDR_BLCK, 0);
        fill_block(&ADDR_ZERO, &ADDR_BLCK, &ADDR_BLCK, 0);
}

/* --- Reference-block indexing (RFC 9106 section 3.4.2, Figures 12/13) -------- */

static uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index,
                            uint32_t segment_length,
                            uint32_t lane_length, uint32_t pseudo_rand,
                            int same_lane)
{
        uint32_t reference_area_size;
        uint64_t relative_position;
        uint32_t start_position, absolute_position;

        if (pass == 0) {
                if (slice == 0) {
                        reference_area_size = index - 1;
                } else if (same_lane) {
                        reference_area_size = slice * segment_length +
                                              index - 1;
                } else {
                        reference_area_size = slice * segment_length +
                                              ((index == 0) ? (uint32_t)-1
                                                            : 0);
                }
        } else {
                if (same_lane) {
                        reference_area_size = lane_length - segment_length +
                                              index - 1;
                } else {
                        reference_area_size = lane_length - segment_length +
                                              ((index == 0) ? (uint32_t)-1
                                                            : 0);
                }
        }

        relative_position = pseudo_rand;
        relative_position = relative_position * relative_position >> 32;
        relative_position = reference_area_size - 1 -
                            (reference_area_size * relative_position >> 32);

        start_position = 0;
        if (pass != 0) {
                start_position = (slice == SYNC_POINTS - 1)
                                     ? 0
                                     : (slice + 1) * segment_length;
        }

        absolute_position = (uint32_t)((start_position + relative_position) %
                                       lane_length);
        return absolute_position;
}

/* --- fill_segment (RFC 9106 section 3.4) ------------------------------------- */

static void fill_segment(block_t *mem, uint32_t lanes, uint32_t passes,
                         uint32_t lane_length, uint32_t segment_length,
                         uint32_t pass, uint32_t slice, uint32_t lane)
{
        uint32_t starting_index = 0;
        uint32_t curr_offset, prev_offset;
        uint32_t i;
        int data_independent_addressing;

        /* Argon2id: the first half-pass (slice 0 and 1 of pass 0) uses the
         * data-independent (Argon2i-style) addressing. */
        data_independent_addressing =
                (pass == 0) && (slice < SYNC_POINTS / 2);

        if (data_independent_addressing) {
                for (i = 0; i < 128; i++) {
                        ADDR_ZERO.v[i] = 0;
                        ADDR_INPT.v[i] = 0;
                }
                ADDR_INPT.v[0] = pass;
                ADDR_INPT.v[1] = lane;
                ADDR_INPT.v[2] = slice;
                ADDR_INPT.v[3] = lanes * lane_length; /* m' */
                ADDR_INPT.v[4] = passes;
                ADDR_INPT.v[5] = TYPE_ARGON2ID;
        }

        if ((pass == 0) && (slice == 0)) {
                starting_index = 2; /* first two blocks are the H' seeds */
                if (data_independent_addressing) {
                        next_addresses(); /* counter becomes 1 */
                }
        }

        curr_offset = lane * lane_length + slice * segment_length +
                      starting_index;
        if (curr_offset % lane_length == 0) {
                prev_offset = curr_offset + lane_length - 1;
        } else {
                prev_offset = curr_offset - 1;
        }

        for (i = starting_index; i < segment_length;
             ++i, ++curr_offset, ++prev_offset) {
                uint64_t pseudo_rand;
                uint32_t ref_index, ref_lane;

                if (curr_offset % lane_length == 1) {
                        prev_offset = curr_offset - 1;
                }

                if (data_independent_addressing) {
                        if (i % ADDRESSES_IN_BLOCK == 0) {
                                next_addresses();
                        }
                        pseudo_rand = ADDR_BLCK.v[i % ADDRESSES_IN_BLOCK];
                } else {
                        pseudo_rand = mem[prev_offset].v[0];
                }

                ref_lane = (uint32_t)((pseudo_rand >> 32) % lanes);
                if ((pass == 0) && (slice == 0)) {
                        ref_lane = lane; /* cannot reference other lanes yet */
                }

                ref_index = index_alpha(pass, slice, i, segment_length,
                                        lane_length,
                                        (uint32_t)(pseudo_rand & 0xFFFFFFFFu),
                                        ref_lane == lane);

                if (pass == 0) {
                        fill_block(&mem[prev_offset],
                                   &mem[ref_lane * lane_length + ref_index],
                                   &mem[curr_offset], 0);
                } else {
                        fill_block(&mem[prev_offset],
                                   &mem[ref_lane * lane_length + ref_index],
                                   &mem[curr_offset], 1);
                }
        }
}

/* --- Public entry ------------------------------------------------------------ */

int red_argon2id(uint8_t *tag, uint32_t tag_len,
                 const void *pwd, uint32_t pwd_len,
                 const void *salt, uint32_t salt_len,
                 const void *secret, uint32_t secret_len,
                 const void *ad, uint32_t ad_len,
                 uint32_t passes, uint32_t memory_kib, uint32_t lanes,
                 void *work, uint32_t work_len)
{
        uint64_t m_prime64;
        uint32_t m_prime, lane_length, segment_length, slice, lane, pass, i;
        block_t *mem;
        uint8_t h0[64];
        uint8_t seedbuf[72];
        block_t final_block;

        /* --- validation before any computation (fail-closed) -------------- */
        if (tag == NULL || pwd == NULL || salt == NULL || work == NULL) {
                return RED_CRYPTO_ERR_NULL;
        }
        if ((secret == NULL && secret_len != 0) ||
            (ad == NULL && ad_len != 0)) {
                return RED_CRYPTO_ERR_NULL;
        }
        if (tag_len < RED_ARGON2_TAG_MIN || tag_len > RED_ARGON2_TAG_MAX) {
                return RED_CRYPTO_ERR_LEN;
        }
        if (salt_len < RED_ARGON2_SALT_MIN || passes < RED_ARGON2_PASS_MIN ||
            lanes == 0 || lanes > RED_ARGON2_LANE_MAX) {
                return RED_CRYPTO_ERR_LEN;
        }
        if (memory_kib < 8u * lanes) {
                return RED_CRYPTO_ERR_LEN; /* RFC: m >= 8*p */
        }
        m_prime64 = 4ULL * lanes * (memory_kib / (4u * lanes));
        /* m' >= 8*lanes follows from memory_kib >= 8*lanes (floor of m/4p
         * cannot drop below 2), so lane_length >= 8 and every slice has
         * segment_length >= 2 — the RFC minimum topology. */
        if (m_prime64 * 1024ULL > (uint64_t)work_len) {
                return RED_CRYPTO_ERR_LEN; /* work area too small */
        }

        m_prime = (uint32_t)m_prime64;
        lane_length = m_prime / lanes;
        segment_length = lane_length / SYNC_POINTS;
        mem = (block_t *)work;

        /* --- 1. H0 --------------------------------------------------------- */
        initial_hash(h0, tag_len, pwd, pwd_len, salt, salt_len, secret,
                     secret_len, ad, ad_len, passes, memory_kib, lanes);

        /* --- 2/3/4. initial blocks B[i][0], B[i][1] ------------------------ */
        for (lane = 0; lane < lanes; lane++) {
                for (i = 0; i < 2; i++) {
                        for (slice = 0; slice < 64; slice++) {
                                seedbuf[slice] = h0[slice];
                        }
                        store32_le(seedbuf + 64, i);
                        store32_le(seedbuf + 68, lane);
                        blake2b_long(&mem[lane * lane_length + i], 1024,
                                     seedbuf, 72);
                }
        }

        /* --- 5/6. slicewise filling (single-threaded, slice-major) --------- */
        for (pass = 0; pass < passes; pass++) {
                for (slice = 0; slice < SYNC_POINTS; slice++) {
                        for (lane = 0; lane < lanes; lane++) {
                                fill_segment(mem, lanes, passes, lane_length,
                                             segment_length, pass, slice,
                                             lane);
                        }
                }
        }

        /* --- 7. final block C = XOR of last column ------------------------- */
        for (i = 0; i < 128; i++) {
                final_block.v[i] = 0;
        }
        for (lane = 0; lane < lanes; lane++) {
                const block_t *last = &mem[lane * lane_length + lane_length -
                                           1];
                for (i = 0; i < 128; i++) {
                        final_block.v[i] ^= last->v[i];
                }
        }

        /* --- 8. tag = H'^T(C) ----------------------------------------------- */
        blake2b_long(tag, tag_len, &final_block, 1024);

        /* Hygiene: scrub the seed material and scratch blocks. The caller
         * owns and must wipe `work` (see red/argon2.h contract). */
        for (i = 0; i < 64; i++) {
                h0[i] = 0;
        }
        for (i = 0; i < 72; i++) {
                seedbuf[i] = 0;
        }
        for (i = 0; i < 128; i++) {
                ADDR_BLCK.v[i] = 0;
                ADDR_INPT.v[i] = 0;
                SCRATCH_R.v[i] = 0;
                SCRATCH_T.v[i] = 0;
        }
        return RED_CRYPTO_OK;
}
