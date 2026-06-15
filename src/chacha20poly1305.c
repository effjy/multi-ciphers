/* XChaCha20-Poly1305 - see header. Public domain / CC0. */
#include "chacha20poly1305.h"
#include <string.h>

/* ---------------- ChaCha20 ---------------- */
static uint32_t load32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32le(uint8_t *p, uint32_t w) {
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define QR(a,b,c,d)                       \
    a += b; d ^= a; d = rotl32(d, 16);    \
    c += d; b ^= c; b = rotl32(b, 12);    \
    a += b; d ^= a; d = rotl32(d, 8);     \
    c += d; b ^= c; b = rotl32(b, 7);

static const uint8_t sigma[16] = "expand 32-byte k";

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    int i;
    for (i = 0; i < 16; i++) out[i] = in[i];
    for (i = 0; i < 10; i++) {
        QR(out[0], out[4], out[ 8], out[12]);
        QR(out[1], out[5], out[ 9], out[13]);
        QR(out[2], out[6], out[10], out[14]);
        QR(out[3], out[7], out[11], out[15]);
        QR(out[0], out[5], out[10], out[15]);
        QR(out[1], out[6], out[11], out[12]);
        QR(out[2], out[7], out[ 8], out[13]);
        QR(out[3], out[4], out[ 9], out[14]);
    }
    for (i = 0; i < 16; i++) out[i] += in[i];
}

static void chacha20_init(uint32_t st[16], const uint8_t key[32],
                          uint32_t counter, const uint8_t nonce[12]) {
    st[0] = load32le(sigma + 0);  st[1] = load32le(sigma + 4);
    st[2] = load32le(sigma + 8);  st[3] = load32le(sigma + 12);
    for (int i = 0; i < 8; i++) st[4 + i] = load32le(key + 4 * i);
    st[12] = counter;
    st[13] = load32le(nonce + 0);
    st[14] = load32le(nonce + 4);
    st[15] = load32le(nonce + 8);
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12]) {
    uint32_t st[16], blk[16];
    uint8_t ks[64];
    chacha20_init(st, key, counter, nonce);
    while (len > 0) {
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32le(ks + 4 * i, blk[i]);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
        out += n; in += n; len -= n;
        st[12]++;
    }
    memset(ks, 0, sizeof(ks));
}

static void hchacha20(uint8_t subkey[32], const uint8_t key[32], const uint8_t nonce16[16]) {
    uint32_t st[16];
    st[0] = load32le(sigma + 0);  st[1] = load32le(sigma + 4);
    st[2] = load32le(sigma + 8);  st[3] = load32le(sigma + 12);
    for (int i = 0; i < 8; i++) st[4 + i] = load32le(key + 4 * i);
    for (int i = 0; i < 4; i++) st[12 + i] = load32le(nonce16 + 4 * i);
    for (int i = 0; i < 10; i++) {
        QR(st[0], st[4], st[ 8], st[12]);
        QR(st[1], st[5], st[ 9], st[13]);
        QR(st[2], st[6], st[10], st[14]);
        QR(st[3], st[7], st[11], st[15]);
        QR(st[0], st[5], st[10], st[15]);
        QR(st[1], st[6], st[11], st[12]);
        QR(st[2], st[7], st[ 8], st[13]);
        QR(st[3], st[4], st[ 9], st[14]);
    }
    for (int i = 0; i < 4; i++) store32le(subkey + 4 * i, st[i]);
    for (int i = 0; i < 4; i++) store32le(subkey + 16 + 4 * i, st[12 + i]);
}

/* ---------------- Poly1305 ---------------- */
typedef struct {
    uint32_t r[5], h[5], pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    st->r[0] = (load32le(key +  0)     ) & 0x3ffffff;
    st->r[1] = (load32le(key +  3) >> 2) & 0x3ffff03;
    st->r[2] = (load32le(key +  6) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32le(key +  9) >> 6) & 0x3f03fff;
    st->r[4] = (load32le(key + 12) >> 8) & 0x00fffff;
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->pad[0] = load32le(key + 16);
    st->pad[1] = load32le(key + 20);
    st->pad[2] = load32le(key + 24);
    st->pad[3] = load32le(key + 28);
    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1UL << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;
        h0 += (load32le(m +  0)     ) & 0x3ffffff;
        h1 += (load32le(m +  3) >> 2) & 0x3ffffff;
        h2 += (load32le(m +  6) >> 4) & 0x3ffffff;
        h3 += (load32le(m +  9) >> 6) & 0x3ffffff;
        h4 += (load32le(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    if (bytes) { memcpy(st->buffer + st->leftover, m, bytes); st->leftover += bytes; }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    f = (uint64_t)h0 + st->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32le(mac +  0, h0); store32le(mac +  4, h1);
    store32le(mac +  8, h2); store32le(mac + 12, h3);
    memset(st, 0, sizeof(*st));
}

/* ---------------- AEAD ---------------- */
static const uint8_t zeropad[16] = {0};

static void poly1305_pad16(poly1305_state *st, size_t len) {
    size_t rem = len & 15;
    if (rem) poly1305_update(st, zeropad, 16 - rem);
}

static void compute_tag(uint8_t tag[16], const uint8_t otk[32],
                        const uint8_t *aad, size_t aadlen,
                        const uint8_t *ct, size_t ctlen) {
    poly1305_state st;
    uint8_t lengths[16];
    poly1305_init(&st, otk);
    poly1305_update(&st, aad, aadlen);
    poly1305_pad16(&st, aadlen);
    poly1305_update(&st, ct, ctlen);
    poly1305_pad16(&st, ctlen);
    store32le(lengths + 0, (uint32_t)aadlen);
    store32le(lengths + 4, (uint32_t)((uint64_t)aadlen >> 32));
    store32le(lengths + 8, (uint32_t)ctlen);
    store32le(lengths + 12, (uint32_t)((uint64_t)ctlen >> 32));
    poly1305_update(&st, lengths, 16);
    poly1305_finish(&st, tag);
}

static void derive(uint8_t subkey[32], uint8_t chacha_nonce[12],
                   const uint8_t key[32], const uint8_t nonce[24]) {
    hchacha20(subkey, key, nonce);
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);
}

void xchacha20poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                               const uint8_t *pt, size_t ptlen,
                               const uint8_t *aad, size_t aadlen,
                               const uint8_t nonce[24], const uint8_t key[32]) {
    uint8_t subkey[32], cn[12], otk[64];
    derive(subkey, cn, key, nonce);
    memset(otk, 0, sizeof(otk));
    chacha20_xor(otk, otk, 32, subkey, 0, cn);  /* Poly1305 one-time key */
    chacha20_xor(ct, pt, ptlen, subkey, 1, cn);
    compute_tag(tag, otk, aad, aadlen, ct, ptlen);
    memset(subkey, 0, sizeof(subkey));
    memset(otk, 0, sizeof(otk));
}

int xchacha20poly1305_decrypt(uint8_t *pt,
                              const uint8_t *ct, size_t ctlen,
                              const uint8_t tag[16],
                              const uint8_t *aad, size_t aadlen,
                              const uint8_t nonce[24], const uint8_t key[32]) {
    uint8_t subkey[32], cn[12], otk[64], expected[16];
    uint8_t diff = 0;
    derive(subkey, cn, key, nonce);
    memset(otk, 0, sizeof(otk));
    chacha20_xor(otk, otk, 32, subkey, 0, cn);
    compute_tag(expected, otk, aad, aadlen, ct, ctlen);
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    if (diff) {
        memset(subkey, 0, sizeof(subkey));
        memset(otk, 0, sizeof(otk));
        return -1;
    }
    chacha20_xor(pt, ct, ctlen, subkey, 1, cn);
    memset(subkey, 0, sizeof(subkey));
    memset(otk, 0, sizeof(otk));
    return 0;
}
