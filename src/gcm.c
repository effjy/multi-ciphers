/* Generic GCM - see gcm.h. Constant-time-ish, table-free GHASH.
 * Public domain. */
#include "gcm.h"
#include <string.h>

/* Multiply X by Y in GF(2^128) using the GCM bit-reflected polynomial. */
static void ghash_mul(uint8_t *X, const uint8_t *Y) {
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, Y, 16);
    for (int i = 0; i < 128; i++) {
        if ((X[i >> 3] >> (7 - (i & 7))) & 1)
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        /* V = V >> 1, with reduction by R = 0xe1 if LSB set */
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; j--) V[j] = (uint8_t)((V[j] >> 1) | (V[j - 1] << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(X, Z, 16);
}

static void ghash_update(uint8_t *acc, const uint8_t *H, const uint8_t *data, size_t len) {
    while (len >= 16) {
        for (int i = 0; i < 16; i++) acc[i] ^= data[i];
        ghash_mul(acc, H);
        data += 16; len -= 16;
    }
    if (len) {
        uint8_t blk[16] = {0};
        memcpy(blk, data, len);
        for (int i = 0; i < 16; i++) acc[i] ^= blk[i];
        ghash_mul(acc, H);
    }
}

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static void incr32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) { if (++ctr[i]) break; }
}

static void gctr(gcm_block_fn enc, const void *cctx, uint8_t ctr[16],
                 const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t ks[16];
    while (len > 0) {
        enc(cctx, ctr, ks);
        size_t n = len < 16 ? len : 16;
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
        in += n; out += n; len -= n;
        incr32(ctr);
    }
}

static void gcm_core(gcm_block_fn enc, const void *cctx, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t len, uint8_t *out,
                     uint8_t tag[16], int do_encrypt, const uint8_t *ct_for_tag) {
    uint8_t H[16] = {0}, J0[16], S[16] = {0}, lenblk[16], ej0[16];
    enc(cctx, H, H);                       /* H = E(0^128) */

    memcpy(J0, nonce, 12);                  /* 96-bit IV: J0 = IV || 0^31 || 1 */
    J0[12] = J0[13] = J0[14] = 0; J0[15] = 1;

    if (do_encrypt) {
        uint8_t ctr[16];
        memcpy(ctr, J0, 16);
        incr32(ctr);
        gctr(enc, cctx, ctr, in, len, out);
    }

    /* GHASH over AAD || ciphertext || lengths */
    ghash_update(S, H, aad, aadlen);
    ghash_update(S, H, do_encrypt ? out : ct_for_tag, len);
    put_be64(lenblk, (uint64_t)aadlen * 8);
    put_be64(lenblk + 8, (uint64_t)len * 8);
    for (int i = 0; i < 16; i++) S[i] ^= lenblk[i];
    ghash_mul(S, H);

    enc(cctx, J0, ej0);
    for (int i = 0; i < 16; i++) tag[i] = S[i] ^ ej0[i];
}

void gcm_encrypt(gcm_block_fn enc, const void *cctx, const uint8_t nonce[12],
                 const uint8_t *aad, size_t aadlen,
                 const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]) {
    gcm_core(enc, cctx, nonce, aad, aadlen, pt, ptlen, ct, tag, 1, NULL);
}

int gcm_decrypt(gcm_block_fn enc, const void *cctx, const uint8_t nonce[12],
                const uint8_t *aad, size_t aadlen,
                const uint8_t *ct, size_t ctlen,
                const uint8_t tag[16], uint8_t *pt) {
    uint8_t expected[16];
    uint8_t diff = 0;
    gcm_core(enc, cctx, nonce, aad, aadlen, NULL, ctlen, NULL, expected, 0, ct);
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    if (diff) return -1;
    /* tag ok -> decrypt with CTR starting at inc32(J0) */
    {
        uint8_t ctr[16];
        memcpy(ctr, nonce, 12);
        ctr[12] = ctr[13] = ctr[14] = 0; ctr[15] = 1;
        incr32(ctr);
        gctr(enc, cctx, ctr, ct, ctlen, pt);
    }
    return 0;
}
