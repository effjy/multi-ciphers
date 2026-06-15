/* Argon2id - see argon2.h. Faithful reimplementation of the reference
 * algorithm (PHC winner, version 1.3). Public domain / CC0. */
#include "argon2.h"
#include "blake2b.h"
#include <stdlib.h>
#include <string.h>

#define ARGON2_BLOCK_SIZE        1024
#define ARGON2_QWORDS_IN_BLOCK   128
#define ARGON2_ADDRESSES_IN_BLOCK 128
#define ARGON2_SYNC_POINTS       4
#define ARGON2_VERSION_13        0x13
#define ARGON2_TYPE_ID           2
#define ARGON2_PREHASH_DIGEST    64

typedef struct { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } block;

static void store32(uint8_t *p, uint32_t w) {
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}
static void store64(uint8_t *p, uint64_t w) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(w >> (8 * i));
}
static uint64_t load64(const uint8_t *p) {
    uint64_t w = 0;
    for (int i = 0; i < 8; i++) w |= (uint64_t)p[i] << (8 * i);
    return w;
}

static void init_block_value(block *b, uint8_t in) { memset(b->v, in, sizeof(b->v)); }
static void copy_block(block *dst, const block *src) { memcpy(dst->v, src->v, sizeof(dst->v)); }
static void xor_block(block *dst, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) dst->v[i] ^= src->v[i];
}
static void load_block(block *dst, const uint8_t *in) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) dst->v[i] = load64(in + i * 8);
}
static void store_block(uint8_t *out, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) store64(out + i * 8, src->v[i]);
}

/* H' : variable-length BLAKE2b hash used throughout Argon2. */
static int blake2b_long(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    uint8_t outlen_bytes[4];
    store32(outlen_bytes, (uint32_t)outlen);
    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_state S;
        blake2b_init(&S, outlen);
        blake2b_update(&S, outlen_bytes, 4);
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, out, outlen);
    } else {
        uint8_t buf[BLAKE2B_OUTBYTES];
        uint8_t tmp[BLAKE2B_OUTBYTES];
        size_t toproduce = outlen - BLAKE2B_OUTBYTES / 2;
        blake2b_state S;
        blake2b_init(&S, BLAKE2B_OUTBYTES);
        blake2b_update(&S, outlen_bytes, 4);
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, buf, BLAKE2B_OUTBYTES);
        memcpy(out, buf, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        while (toproduce > BLAKE2B_OUTBYTES) {
            memcpy(tmp, buf, BLAKE2B_OUTBYTES);
            blake2b(buf, BLAKE2B_OUTBYTES, tmp, BLAKE2B_OUTBYTES, NULL, 0);
            memcpy(out, buf, BLAKE2B_OUTBYTES / 2);
            out += BLAKE2B_OUTBYTES / 2;
            toproduce -= BLAKE2B_OUTBYTES / 2;
        }
        memcpy(tmp, buf, BLAKE2B_OUTBYTES);
        blake2b(buf, toproduce, tmp, BLAKE2B_OUTBYTES, NULL, 0);
        memcpy(out, buf, toproduce);
    }
    return 0;
}

/* ---- compression function G ---- */
static uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }
static uint64_t fBlaMka(uint64_t x, uint64_t y) {
    const uint64_t m = 0xFFFFFFFFULL;
    return x + y + 2ULL * (x & m) * (y & m);
}

#define G_(a,b,c,d)                       \
    do {                                  \
        a = fBlaMka(a, b);                \
        d = rotr64(d ^ a, 32);            \
        c = fBlaMka(c, d);                \
        b = rotr64(b ^ c, 24);            \
        a = fBlaMka(a, b);                \
        d = rotr64(d ^ a, 16);            \
        c = fBlaMka(c, d);                \
        b = rotr64(b ^ c, 63);            \
    } while (0)

#define BLAKE2_ROUND(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) \
    do {                                  \
        G_(v0, v4,  v8, v12);             \
        G_(v1, v5,  v9, v13);             \
        G_(v2, v6, v10, v14);             \
        G_(v3, v7, v11, v15);             \
        G_(v0, v5, v10, v15);             \
        G_(v1, v6, v11, v12);             \
        G_(v2, v7,  v8, v13);             \
        G_(v3, v4,  v9, v14);             \
    } while (0)

static void fill_block(const block *prev, const block *ref, block *next, int with_xor) {
    block R, tmp;
    int i;
    copy_block(&R, ref);
    xor_block(&R, prev);
    copy_block(&tmp, &R);
    if (with_xor) xor_block(&tmp, next);

    /* Apply BLAKE2 round on each row of 16 qwords (columns of the matrix). */
    for (i = 0; i < 8; i++) {
        uint64_t *p = R.v + 16 * i;
        BLAKE2_ROUND(p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                     p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
    }
    /* Apply BLAKE2 round on each column (rows of the matrix). */
    for (i = 0; i < 8; i++) {
        uint64_t *v = R.v;
        BLAKE2_ROUND(v[2*i], v[2*i+1], v[2*i+16], v[2*i+17],
                     v[2*i+32], v[2*i+33], v[2*i+48], v[2*i+49],
                     v[2*i+64], v[2*i+65], v[2*i+80], v[2*i+81],
                     v[2*i+96], v[2*i+97], v[2*i+112], v[2*i+113]);
    }
    copy_block(next, &tmp);
    xor_block(next, &R);
}

typedef struct {
    block   *memory;
    uint32_t memory_blocks;
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t passes;
} instance_t;

typedef struct { uint32_t pass, lane, slice, index; } position_t;

static void next_addresses(block *address, block *input, const block *zero) {
    input->v[6]++;
    fill_block(zero, input, address, 0);
    fill_block(zero, address, address, 0);
}

static uint32_t index_alpha(const instance_t *inst, const position_t *pos,
                            uint32_t pseudo_rand, int same_lane) {
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (pos->pass == 0) {
        if (pos->slice == 0) {
            reference_area_size = pos->index - 1;
        } else if (same_lane) {
            reference_area_size = pos->slice * inst->segment_length + pos->index - 1;
        } else {
            reference_area_size = pos->slice * inst->segment_length +
                                  (pos->index == 0 ? (uint32_t)-1 : 0);
        }
    } else {
        if (same_lane) {
            reference_area_size = inst->lane_length - inst->segment_length + pos->index - 1;
        } else {
            reference_area_size = inst->lane_length - inst->segment_length +
                                  (pos->index == 0 ? (uint32_t)-1 : 0);
        }
    }

    relative_position = pseudo_rand;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = reference_area_size - 1 -
                        ((reference_area_size * relative_position) >> 32);

    start_position = 0;
    if (pos->pass != 0)
        start_position = (pos->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0 : (pos->slice + 1) * inst->segment_length;

    absolute_position = (uint32_t)((start_position + relative_position) % inst->lane_length);
    return absolute_position;
}

static void fill_segment(const instance_t *inst, position_t pos) {
    block address, input, zero;
    uint64_t pseudo_rand, ref_lane, ref_index;
    uint32_t prev_offset, curr_offset, starting_index, i;
    int data_independent;

    data_independent = (pos.pass == 0) && (pos.slice < ARGON2_SYNC_POINTS / 2);

    if (data_independent) {
        init_block_value(&zero, 0);
        init_block_value(&input, 0);
        input.v[0] = pos.pass;
        input.v[1] = pos.lane;
        input.v[2] = pos.slice;
        input.v[3] = inst->memory_blocks;
        input.v[4] = inst->passes;
        input.v[5] = ARGON2_TYPE_ID;
    }

    starting_index = 0;
    if (pos.pass == 0 && pos.slice == 0) {
        starting_index = 2;
        if (data_independent) next_addresses(&address, &input, &zero);
    }

    curr_offset = pos.lane * inst->lane_length +
                  pos.slice * inst->segment_length + starting_index;
    prev_offset = (curr_offset % inst->lane_length == 0)
                      ? curr_offset + inst->lane_length - 1
                      : curr_offset - 1;

    for (i = starting_index; i < inst->segment_length; i++, curr_offset++, prev_offset++) {
        if (curr_offset % inst->lane_length == 1)
            prev_offset = curr_offset - 1;

        if (data_independent) {
            if (i % ARGON2_ADDRESSES_IN_BLOCK == 0)
                next_addresses(&address, &input, &zero);
            pseudo_rand = address.v[i % ARGON2_ADDRESSES_IN_BLOCK];
        } else {
            pseudo_rand = inst->memory[prev_offset].v[0];
        }

        ref_lane = (pseudo_rand >> 32) % inst->lanes;
        if (pos.pass == 0 && pos.slice == 0) ref_lane = pos.lane;

        pos.index = i;
        ref_index = index_alpha(inst, &pos, (uint32_t)(pseudo_rand & 0xFFFFFFFF),
                                ref_lane == pos.lane);

        block *ref = inst->memory + inst->lane_length * ref_lane + ref_index;
        block *cur = inst->memory + curr_offset;
        fill_block(inst->memory + prev_offset, ref, cur, pos.pass != 0);
    }
}

static void initial_hash(uint8_t H0[ARGON2_PREHASH_DIGEST],
                         size_t outlen, const void *pwd, size_t pwdlen,
                         const void *salt, size_t saltlen,
                         uint32_t t, uint32_t m, uint32_t lanes) {
    blake2b_state S;
    uint8_t v[4];
    blake2b_init(&S, ARGON2_PREHASH_DIGEST);
    store32(v, lanes);            blake2b_update(&S, v, 4);
    store32(v, (uint32_t)outlen); blake2b_update(&S, v, 4);
    store32(v, m);                blake2b_update(&S, v, 4);
    store32(v, t);                blake2b_update(&S, v, 4);
    store32(v, ARGON2_VERSION_13);blake2b_update(&S, v, 4);
    store32(v, ARGON2_TYPE_ID);   blake2b_update(&S, v, 4);
    store32(v, (uint32_t)pwdlen); blake2b_update(&S, v, 4);
    blake2b_update(&S, pwd, pwdlen);
    store32(v, (uint32_t)saltlen);blake2b_update(&S, v, 4);
    blake2b_update(&S, salt, saltlen);
    store32(v, 0);                blake2b_update(&S, v, 4); /* secret length */
    store32(v, 0);                blake2b_update(&S, v, 4); /* assoc data len */
    blake2b_final(&S, H0, ARGON2_PREHASH_DIGEST);
}

int argon2id_hash(void *out, size_t outlen,
                  const void *pwd, size_t pwdlen,
                  const void *salt, size_t saltlen,
                  uint32_t t_cost, uint32_t m_cost, uint32_t lanes) {
    if (outlen == 0 || lanes == 0 || t_cost == 0) return -1;
    /* Bound parameters to prevent integer overflow / runaway allocation when
     * they originate from an untrusted file header on decryption.
     *   lanes  : keeps 8*lanes and 4*lanes within uint32 (no overflow)
     *   m_cost : caps memory at 16 GiB (KiB units) so calloc cannot be coaxed
     *            into absurd sizes; legitimate profiles use at most 2 GiB
     *   t_cost : caps the number of passes (anti-DoS) */
    if (lanes  > 0xFFFFFFu)        return -1;
    if (t_cost > 0xFFFFFFu)        return -1;
    if (m_cost > 16u * 1024 * 1024) return -1;

    uint32_t memory_blocks = m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * lanes)
        memory_blocks = 2 * ARGON2_SYNC_POINTS * lanes;
    uint32_t segment_length = memory_blocks / (lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * lanes * ARGON2_SYNC_POINTS;
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;

    block *memory = calloc(memory_blocks, sizeof(block));
    if (!memory) return -1;

    instance_t inst = { memory, memory_blocks, segment_length, lane_length, lanes, t_cost };

    /* H0 and the first two blocks of each lane. */
    uint8_t H0[ARGON2_PREHASH_DIGEST + 8];
    initial_hash(H0, outlen, pwd, pwdlen, salt, saltlen, t_cost, m_cost, lanes);

    uint8_t blockbytes[ARGON2_BLOCK_SIZE];
    for (uint32_t l = 0; l < lanes; l++) {
        store32(H0 + ARGON2_PREHASH_DIGEST, 0);
        store32(H0 + ARGON2_PREHASH_DIGEST + 4, l);
        blake2b_long(blockbytes, ARGON2_BLOCK_SIZE, H0, sizeof(H0));
        load_block(&memory[l * lane_length + 0], blockbytes);

        store32(H0 + ARGON2_PREHASH_DIGEST, 1);
        blake2b_long(blockbytes, ARGON2_BLOCK_SIZE, H0, sizeof(H0));
        load_block(&memory[l * lane_length + 1], blockbytes);
    }

    /* Fill memory. */
    for (uint32_t pass = 0; pass < t_cost; pass++)
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++)
            for (uint32_t lane = 0; lane < lanes; lane++) {
                position_t pos = { pass, lane, slice, 0 };
                fill_segment(&inst, pos);
            }

    /* Finalize: XOR last block of every lane, then H'. */
    block final;
    copy_block(&final, &memory[lane_length - 1]);
    for (uint32_t l = 1; l < lanes; l++)
        xor_block(&final, &memory[l * lane_length + (lane_length - 1)]);

    store_block(blockbytes, &final);
    blake2b_long((uint8_t *)out, outlen, blockbytes, ARGON2_BLOCK_SIZE);

    /* Wipe. */
    memset(memory, 0, (size_t)memory_blocks * sizeof(block));
    free(memory);
    memset(blockbytes, 0, sizeof(blockbytes));
    memset(H0, 0, sizeof(H0));
    return 0;
}
