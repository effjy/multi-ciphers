/* Serpent encryption + key schedule. See serpent.h.
 *
 * The S-box boolean equations (S0..S7) and linear-transform are the canonical
 * Serpent formulas published by Dag Arne Osvik; the round and key-schedule
 * structure follow the Serpent specification (Anderson/Biham/Knudsen). These
 * equations are identical across the public-domain reference implementations.
 */
#include "serpent.h"
#include <string.h>

#define PHI 0x9e3779b9UL

static uint32_t rol32(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store_le32(uint8_t *p, uint32_t w) {
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

/* ---- S-boxes (forward) ---- */
#define S0(x0, x1, x2, x3, x4) { \
    x4 = x3; x3 |= x0; x0 ^= x4; x4 ^= x2; x4 = ~x4; x3 ^= x1; x1 &= x0; \
    x1 ^= x4; x2 ^= x0; x0 ^= x3; x4 |= x0; x0 ^= x2; x2 &= x1; \
    x3 ^= x2; x1 = ~x1; x2 ^= x4; x1 ^= x2; }
#define S1(x0, x1, x2, x3, x4) { \
    x4 = x1; x1 ^= x0; x0 ^= x3; x3 = ~x3; x4 &= x1; x0 |= x1; x3 ^= x2; \
    x0 ^= x3; x1 ^= x3; x3 ^= x4; x1 |= x4; x4 ^= x2; x2 &= x0; \
    x2 ^= x1; x1 |= x0; x0 = ~x0; x0 ^= x2; x4 ^= x1; }
#define S2(x0, x1, x2, x3, x4) { \
    x3 = ~x3; x1 ^= x0; x4 = x0; x0 &= x2; x0 ^= x3; x3 |= x4; x2 ^= x1; \
    x3 ^= x1; x1 &= x0; x0 ^= x2; x2 &= x3; x3 |= x1; x0 = ~x0; \
    x3 ^= x0; x4 ^= x0; x0 ^= x2; x1 |= x2; }
#define S3(x0, x1, x2, x3, x4) { \
    x4 = x1; x1 ^= x3; x3 |= x0; x4 &= x0; x0 ^= x2; x2 ^= x1; x1 &= x3; \
    x2 ^= x3; x0 |= x4; x4 ^= x3; x1 ^= x0; x0 &= x3; x3 &= x4; \
    x3 ^= x2; x4 |= x1; x2 &= x1; x4 ^= x3; x0 ^= x3; x3 ^= x2; }
#define S4(x0, x1, x2, x3, x4) { \
    x4 = x3; x3 &= x0; x0 ^= x4; x3 ^= x2; x2 |= x4; x0 ^= x1; x4 ^= x3; \
    x2 |= x0; x2 ^= x1; x1 &= x0; x1 ^= x4; x4 &= x2; x2 ^= x3; \
    x4 ^= x0; x3 |= x1; x1 = ~x1; x3 ^= x0; }
#define S5(x0, x1, x2, x3, x4) { \
    x4 = x1; x1 |= x0; x2 ^= x1; x3 = ~x3; x4 ^= x0; x0 ^= x2; x1 &= x4; \
    x4 |= x3; x4 ^= x0; x0 &= x3; x1 ^= x3; x3 ^= x2; x0 ^= x1; \
    x2 &= x4; x1 ^= x2; x2 &= x0; x3 ^= x2; }
#define S6(x0, x1, x2, x3, x4) { \
    x4 = x1; x3 ^= x0; x1 ^= x2; x2 ^= x0; x0 &= x3; x1 |= x3; x4 = ~x4; \
    x0 ^= x1; x1 ^= x2; x3 ^= x4; x4 ^= x0; x2 &= x0; x4 ^= x1; \
    x2 ^= x3; x3 &= x1; x3 ^= x0; x1 ^= x2; }
#define S7(x0, x1, x2, x3, x4) { \
    x1 = ~x1; x4 = x1; x0 = ~x0; x1 &= x2; x1 ^= x3; x3 |= x4; x4 ^= x2; \
    x2 ^= x3; x3 ^= x0; x0 |= x1; x2 &= x0; x0 ^= x4; x4 ^= x3; \
    x3 &= x0; x4 ^= x1; x2 ^= x4; x3 ^= x1; x4 |= x0; x4 ^= x1; }

/* linear transform (forward) */
#define LT(x0, x1, x2, x3) { \
    x0 = rol32(x0, 13); x2 = rol32(x2, 3); x1 ^= x0 ^ x2; x3 ^= x2 ^ (x0 << 3); \
    x1 = rol32(x1, 1); x3 = rol32(x3, 7); x0 ^= x1 ^ x3; x2 ^= x3 ^ (x1 << 7); \
    x0 = rol32(x0, 5); x2 = rol32(x2, 22); }

void serpent_setkey(serpent_ctx *ctx, const uint8_t *key, unsigned keylen) {
    uint32_t *k = ctx->expkey;
    uint8_t kb[32];
    uint32_t w[140];
    int i;

    /* Pad key to 256 bits: copy, append 0x01, then zeros. */
    memset(kb, 0, sizeof(kb));
    if (keylen > 32) keylen = 32;
    memcpy(kb, key, keylen);
    if (keylen < 32) kb[keylen] = 0x01;

    for (i = 0; i < 8; i++) w[i] = load_le32(kb + 4 * i);

    /* Prekey expansion: produce w[8..139] (== prekeys 0..131). */
    for (i = 8; i < 140; i++) {
        uint32_t t = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (uint32_t)(i - 8);
        w[i] = rol32(t, 11);
    }

    /* Apply S-boxes to prekeys to get the 33 round keys (132 words). The
     * S-box used for round-key group i is S(3 - i mod 8). */
    {
        uint32_t *p = w + 8; /* p[0..131] are the prekeys */
        for (i = 0; i < 33; i++) {
            uint32_t a = p[4*i+0], b = p[4*i+1], c = p[4*i+2], d = p[4*i+3], e = 0;
            /* outputs (X0,X1,X2,X3) per the positional mapping of each S-box */
            switch ((32 + 3 - i) % 8) {
            case 0: S0(a,b,c,d,e); k[4*i+0]=c; k[4*i+1]=b; k[4*i+2]=d; k[4*i+3]=a; break;
            case 1: S1(a,b,c,d,e); k[4*i+0]=e; k[4*i+1]=c; k[4*i+2]=d; k[4*i+3]=a; break;
            case 2: S2(a,b,c,d,e); k[4*i+0]=e; k[4*i+1]=b; k[4*i+2]=a; k[4*i+3]=d; break;
            case 3: S3(a,b,c,d,e); k[4*i+0]=d; k[4*i+1]=e; k[4*i+2]=b; k[4*i+3]=a; break;
            case 4: S4(a,b,c,d,e); k[4*i+0]=b; k[4*i+1]=c; k[4*i+2]=d; k[4*i+3]=e; break;
            case 5: S5(a,b,c,d,e); k[4*i+0]=e; k[4*i+1]=a; k[4*i+2]=b; k[4*i+3]=d; break;
            case 6: S6(a,b,c,d,e); k[4*i+0]=c; k[4*i+1]=e; k[4*i+2]=b; k[4*i+3]=d; break;
            case 7: S7(a,b,c,d,e); k[4*i+0]=e; k[4*i+1]=c; k[4*i+2]=d; k[4*i+3]=a; break;
            }
        }
    }
    memset(kb, 0, sizeof(kb));
    memset(w, 0, sizeof(w));
}

void serpent_encrypt_block(const serpent_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    const uint32_t *k = ctx->expkey;
    uint32_t x0 = load_le32(in + 0), x1 = load_le32(in + 4);
    uint32_t x2 = load_le32(in + 8), x3 = load_le32(in + 12);
    uint32_t e;
    int i;

    for (i = 0; i < 32; i++) {
        uint32_t a, b, c, d;
        x0 ^= k[4*i+0]; x1 ^= k[4*i+1]; x2 ^= k[4*i+2]; x3 ^= k[4*i+3];
        e = 0;
        switch (i % 8) {
        case 0: S0(x0,x1,x2,x3,e); a=x2; b=x1; c=x3; d=x0; break;
        case 1: S1(x0,x1,x2,x3,e); a=e;  b=x2; c=x3; d=x0; break;
        case 2: S2(x0,x1,x2,x3,e); a=e;  b=x1; c=x0; d=x3; break;
        case 3: S3(x0,x1,x2,x3,e); a=x3; b=e;  c=x1; d=x0; break;
        case 4: S4(x0,x1,x2,x3,e); a=x1; b=x2; c=x3; d=e;  break;
        case 5: S5(x0,x1,x2,x3,e); a=e;  b=x0; c=x1; d=x3; break;
        case 6: S6(x0,x1,x2,x3,e); a=x2; b=e;  c=x1; d=x3; break;
        default:S7(x0,x1,x2,x3,e); a=e;  b=x2; c=x3; d=x0; break;
        }
        x0 = a; x1 = b; x2 = c; x3 = d;
        if (i < 31) { LT(x0, x1, x2, x3); }
    }
    /* final whitening key (round 32) */
    x0 ^= k[128]; x1 ^= k[129]; x2 ^= k[130]; x3 ^= k[131];

    store_le32(out + 0, x0); store_le32(out + 4, x1);
    store_le32(out + 8, x2); store_le32(out + 12, x3);
}
