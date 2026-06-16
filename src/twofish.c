/* Twofish-256 forward block encryption (public-domain algorithm).
 * Implemented from the specification; verified against the official
 * 256-bit ECB known-answer test vector in selftest.c. */
#include "twofish.h"
#include <string.h>

#define ROL32(x,n) ((uint32_t)(((x)<<(n)) | ((x)>>(32-(n)))))
#define ROR32(x,n) ((uint32_t)(((x)>>(n)) | ((x)<<(32-(n)))))

/* 4-bit boxes that generate the q permutations (from the Twofish spec). */
static const uint8_t Q0T[4][16] = {
    {0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4},
    {0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD},
    {0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1},
    {0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA}
};
static const uint8_t Q1T[4][16] = {
    {0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5},
    {0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8},
    {0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF},
    {0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA}
};

static uint8_t Q0[256], Q1[256];
static int tables_ready = 0;

static uint8_t qperm(const uint8_t t[4][16], uint8_t x) {
    uint8_t a0 = x >> 4, b0 = x & 0xF;
    uint8_t a1 = a0 ^ b0;
    uint8_t b1 = (uint8_t)((a0 ^ (((b0 >> 1) | (b0 << 3)) & 0xF) ^ ((a0 & 1) << 3)) & 0xF);
    uint8_t a2 = t[0][a1], b2 = t[1][b1];
    uint8_t a3 = a2 ^ b2;
    uint8_t b3 = (uint8_t)((a2 ^ (((b2 >> 1) | (b2 << 3)) & 0xF) ^ ((a2 & 1) << 3)) & 0xF);
    uint8_t a4 = t[2][a3], b4 = t[3][b3];
    return (uint8_t)((b4 << 4) | a4);
}

static void build_tables(void) {
    for (int i = 0; i < 256; i++) {
        Q0[i] = qperm(Q0T, (uint8_t)i);
        Q1[i] = qperm(Q1T, (uint8_t)i);
    }
    tables_ready = 1;
}

/* GF(2^8) multiply; poly is the low 8 bits of the reduction polynomial. */
static uint8_t gfmul(uint8_t a, uint8_t b, uint8_t poly) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        b >>= 1;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= poly;
    }
    return r;
}

/* MDS matrix multiply (poly v(x)=0x169 -> reduction byte 0x69). */
static uint32_t mds(uint8_t y0, uint8_t y1, uint8_t y2, uint8_t y3) {
    const uint8_t P = 0x69;
    uint8_t z0 = (uint8_t)(y0 ^ gfmul(y1,0xEF,P) ^ gfmul(y2,0x5B,P) ^ gfmul(y3,0x5B,P));
    uint8_t z1 = (uint8_t)(gfmul(y0,0x5B,P) ^ gfmul(y1,0xEF,P) ^ gfmul(y2,0xEF,P) ^ y3);
    uint8_t z2 = (uint8_t)(gfmul(y0,0xEF,P) ^ gfmul(y1,0x5B,P) ^ y2 ^ gfmul(y3,0xEF,P));
    uint8_t z3 = (uint8_t)(gfmul(y0,0xEF,P) ^ y1 ^ gfmul(y2,0xEF,P) ^ gfmul(y3,0x5B,P));
    return (uint32_t)z0 | ((uint32_t)z1<<8) | ((uint32_t)z2<<16) | ((uint32_t)z3<<24);
}

/* RS code (poly w(x)=0x14D -> reduction byte 0x4D): 8 key bytes -> S word. */
static uint32_t rs_mul(const uint8_t m[8]) {
    static const uint8_t RS[4][8] = {
        {0x01,0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E},
        {0xA4,0x56,0x82,0xF3,0x1E,0xC6,0x68,0xE5},
        {0x02,0xA1,0xFC,0xC1,0x47,0xAE,0x3D,0x19},
        {0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E,0x03}
    };
    uint8_t s[4];
    for (int j = 0; j < 4; j++) {
        uint8_t acc = 0;
        for (int i = 0; i < 8; i++) acc ^= gfmul(RS[j][i], m[i], 0x4D);
        s[j] = acc;
    }
    return (uint32_t)s[0] | ((uint32_t)s[1]<<8) | ((uint32_t)s[2]<<16) | ((uint32_t)s[3]<<24);
}

#define B0(x) ((uint8_t)((x)))
#define B1(x) ((uint8_t)((x)>>8))
#define B2(x) ((uint8_t)((x)>>16))
#define B3(x) ((uint8_t)((x)>>24))

/* h function for k=4 (256-bit key). L is a 4-word key list. */
static uint32_t h(uint32_t X, const uint32_t L[4]) {
    uint8_t y0 = B0(X), y1 = B1(X), y2 = B2(X), y3 = B3(X);

    /* k = 4 */
    y0 = Q1[y0] ^ B0(L[3]); y1 = Q0[y1] ^ B1(L[3]);
    y2 = Q0[y2] ^ B2(L[3]); y3 = Q1[y3] ^ B3(L[3]);
    /* k = 3 */
    y0 = Q1[y0] ^ B0(L[2]); y1 = Q1[y1] ^ B1(L[2]);
    y2 = Q0[y2] ^ B2(L[2]); y3 = Q0[y3] ^ B3(L[2]);
    /* k = 2 (final two q layers + L1,L0) */
    y0 = Q1[Q0[Q0[y0] ^ B0(L[1])] ^ B0(L[0])];
    y1 = Q0[Q0[Q1[y1] ^ B1(L[1])] ^ B1(L[0])];
    y2 = Q1[Q1[Q0[y2] ^ B2(L[1])] ^ B2(L[0])];
    y3 = Q0[Q1[Q1[y3] ^ B3(L[1])] ^ B3(L[0])];

    return mds(y0, y1, y2, y3);
}

static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

void twofish_setkey(twofish_ctx *ctx, const uint8_t key[32]) {
    if (!tables_ready) build_tables();

    uint32_t Me[4], Mo[4];
    for (int i = 0; i < 4; i++) {
        Me[i] = ld32(key + 8*i);       /* even words M0,M2,M4,M6 */
        Mo[i] = ld32(key + 8*i + 4);   /* odd  words M1,M3,M5,M7 */
    }

    /* S vector: RS over each 8-byte group, stored reversed (S3,S2,S1,S0). */
    uint32_t Stmp[4];
    for (int i = 0; i < 4; i++) Stmp[i] = rs_mul(key + 8*i);
    for (int i = 0; i < 4; i++) ctx->S[i] = Stmp[3 - i];

    const uint32_t rho = 0x01010101u;
    for (int i = 0; i < 20; i++) {
        uint32_t A = h((uint32_t)(2*i)   * rho, Me);
        uint32_t B = h((uint32_t)(2*i+1) * rho, Mo);
        B = ROL32(B, 8);
        ctx->K[2*i]   = A + B;
        ctx->K[2*i+1] = ROL32(A + 2*B, 9);
    }
}

void twofish_encrypt_block(const twofish_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint32_t R0 = ld32(in)      ^ ctx->K[0];
    uint32_t R1 = ld32(in + 4)  ^ ctx->K[1];
    uint32_t R2 = ld32(in + 8)  ^ ctx->K[2];
    uint32_t R3 = ld32(in + 12) ^ ctx->K[3];

    for (int r = 0; r < 16; r++) {
        uint32_t T0 = h(R0, ctx->S);
        uint32_t T1 = h(ROL32(R1, 8), ctx->S);
        uint32_t F0 = T0 + T1 + ctx->K[2*r + 8];
        uint32_t F1 = T0 + 2*T1 + ctx->K[2*r + 9];
        uint32_t n2 = ROR32(R2 ^ F0, 1);
        uint32_t n3 = ROL32(R3, 1) ^ F1;
        /* swap halves for next round */
        R2 = R0; R3 = R1; R0 = n2; R1 = n3;
    }

    /* undo final swap, then output whitening */
    st32(out,      R2 ^ ctx->K[4]);
    st32(out + 4,  R3 ^ ctx->K[5]);
    st32(out + 8,  R0 ^ ctx->K[6]);
    st32(out + 12, R1 ^ ctx->K[7]);
}
