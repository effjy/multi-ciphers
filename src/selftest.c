/* Built-in known-answer and round-trip self tests. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "serpent.h"
#include "twofish.h"
#include "gcm.h"
#include "chacha20poly1305.h"
#include "argon2.h"

static int eq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n) == 0; }

static void hexdump(const char *label, const uint8_t *p, size_t n) {
    fprintf(stderr, "  %s: ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n");
}

static void aes_blk(const void *c, const uint8_t in[16], uint8_t out[16]) {
    aes256_encrypt_block((const aes256_ctx *)c, in, out);
}
static void serpent_blk(const void *c, const uint8_t in[16], uint8_t out[16]) {
    serpent_encrypt_block((const serpent_ctx *)c, in, out);
}
static void twofish_blk(const void *c, const uint8_t in[16], uint8_t out[16]) {
    twofish_encrypt_block((const twofish_ctx *)c, in, out);
}

static int test_aes_block(void) {
    /* FIPS-197 AES-256 example */
    uint8_t key[32], pt[16], ct[16], exp[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    const uint8_t p[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                           0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t e[16] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
                           0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
    memcpy(pt, p, 16); memcpy(exp, e, 16);
    aes256_ctx c; aes256_init(&c, key);
    aes256_encrypt_block(&c, pt, ct);
    if (!eq(ct, exp, 16)) { fprintf(stderr,"FAIL AES-256 block KAT\n"); hexdump("got",ct,16); return 1; }
    fprintf(stderr, "ok   AES-256 block KAT (FIPS-197)\n");
    return 0;
}

static int test_serpent_block(void) {
    /* libtomcrypt Serpent-256 KAT */
    uint8_t key[32] = {0x80}; /* 0x80 then zeros */
    uint8_t pt[16] = {0}, ct[16];
    const uint8_t exp[16] = {0xA2,0x23,0xAA,0x12,0x88,0x46,0x3C,0x0E,
                             0x2B,0xE3,0x8E,0xBD,0x82,0x56,0x16,0xC0};
    serpent_ctx c; serpent_setkey(&c, key, 32);
    serpent_encrypt_block(&c, pt, ct);
    if (!eq(ct, exp, 16)) { fprintf(stderr,"FAIL Serpent-256 block KAT\n"); hexdump("got",ct,16); return 1; }
    fprintf(stderr, "ok   Serpent-256 block KAT\n");
    return 0;
}

static int test_twofish_block(void) {
    /* Official Twofish 256-bit ECB KAT: key=0, pt=0. */
    uint8_t key[32] = {0}, pt[16] = {0}, ct[16];
    const uint8_t exp[16] = {0x57,0xFF,0x73,0x9D,0x4D,0xC9,0x2C,0x1B,
                             0xD7,0xFC,0x01,0x70,0x0C,0xC8,0x21,0x6F};
    twofish_ctx c; twofish_setkey(&c, key);
    twofish_encrypt_block(&c, pt, ct);
    if (!eq(ct, exp, 16)) { fprintf(stderr,"FAIL Twofish-256 block KAT\n"); hexdump("got",ct,16); return 1; }
    fprintf(stderr, "ok   Twofish-256 block KAT\n");
    return 0;
}

static int test_gcm_roundtrip(const char *name, gcm_block_fn fn, const void *ctx) {
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t aad[13] = "header-bytes!";
    uint8_t pt[100], ct[100], rt[100], tag[16];
    for (int i = 0; i < 100; i++) pt[i] = (uint8_t)(i*7+1);
    gcm_encrypt(fn, ctx, nonce, aad, sizeof(aad), pt, sizeof(pt), ct, tag);
    if (gcm_decrypt(fn, ctx, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, rt) != 0 ||
        !eq(pt, rt, sizeof(pt))) {
        fprintf(stderr, "FAIL %s round-trip\n", name); return 1;
    }
    tag[0] ^= 0x01;
    if (gcm_decrypt(fn, ctx, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, rt) == 0) {
        fprintf(stderr, "FAIL %s tamper not detected\n", name); return 1;
    }
    fprintf(stderr, "ok   %s round-trip + tamper detection\n", name);
    return 0;
}

static int test_xchacha_roundtrip(void) {
    uint8_t key[32], nonce[24], aad[13] = "header-bytes!";
    uint8_t pt[100], ct[100], rt[100], tag[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i+1);
    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(i*3);
    for (int i = 0; i < 100; i++) pt[i] = (uint8_t)(i*5+2);
    xchacha20poly1305_encrypt(ct, tag, pt, sizeof(pt), aad, sizeof(aad), nonce, key);
    if (xchacha20poly1305_decrypt(rt, ct, sizeof(ct), tag, aad, sizeof(aad), nonce, key) != 0 ||
        !eq(pt, rt, sizeof(pt))) {
        fprintf(stderr, "FAIL XChaCha20-Poly1305 round-trip\n"); return 1;
    }
    tag[5] ^= 0x80;
    if (xchacha20poly1305_decrypt(rt, ct, sizeof(ct), tag, aad, sizeof(aad), nonce, key) == 0) {
        fprintf(stderr, "FAIL XChaCha20-Poly1305 tamper not detected\n"); return 1;
    }
    fprintf(stderr, "ok   XChaCha20-Poly1305 round-trip + tamper detection\n");
    return 0;
}

static int test_xchacha_kat(void) {
    /* draft-irtf-cfrg-xchacha-03, section A.3.1 (tag check). */
    uint8_t key[32], nonce[24];
    uint8_t aad[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    const char *msg = "Ladies and Gentlemen of the class of '99: If I could offer you "
                      "only one tip for the future, sunscreen would be it.";
    size_t mlen = strlen(msg);
    uint8_t ct[200], tag[16];
    const uint8_t exp_tag[16] = {0xc0,0x87,0x59,0x24,0xc1,0xc7,0x98,0x79,
                                 0x47,0xde,0xaf,0xd8,0x78,0x0a,0xcf,0x49};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    const uint8_t n[24] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,
                           0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57};
    memcpy(nonce, n, 24);
    xchacha20poly1305_encrypt(ct, tag, (const uint8_t *)msg, mlen, aad, sizeof(aad), nonce, key);
    if (!eq(tag, exp_tag, 16)) {
        fprintf(stderr, "FAIL XChaCha20-Poly1305 KAT (tag mismatch)\n");
        hexdump("got tag", tag, 16);
        return 1;
    }
    fprintf(stderr, "ok   XChaCha20-Poly1305 KAT (draft-irtf-cfrg-xchacha A.3.1)\n");
    return 0;
}

static int test_argon2(void) {
    /* RFC 9106 / reference Argon2id KAT, but with empty secret and AD
     * (which this build does not use). Verified against the argon2 reference
     * library invoked with no secret/associated data. */
    uint8_t pwd[32], salt[16], out[32];
    memset(pwd, 0x01, sizeof(pwd));
    memset(salt, 0x02, sizeof(salt));
    const uint8_t exp[32] = {
        0x03,0xaa,0xb9,0x65,0xc1,0x20,0x01,0xc9,0xd7,0xd0,0xd2,0xde,0x33,0x19,0x2c,0x04,
        0x94,0xb6,0x84,0xbb,0x14,0x81,0x96,0xd7,0x3c,0x1d,0xf1,0xac,0xaf,0x6d,0x0c,0x2e };
    if (argon2id_hash(out, 32, pwd, 32, salt, 16, 3, 32, 4) != 0) {
        fprintf(stderr, "FAIL Argon2id (error)\n"); return 1;
    }
    if (!eq(out, exp, 32)) {
        fprintf(stderr, "FAIL Argon2id KAT\n"); hexdump("got", out, 32); return 1;
    }
    fprintf(stderr, "ok   Argon2id KAT\n");
    return 0;
}

int mc_selftest(void) {
    int fails = 0;
    fprintf(stderr, "Multi Ciphers self-test:\n");
    fails += test_aes_block();
    fails += test_serpent_block();
    fails += test_twofish_block();

    {
        uint8_t key[32]; for (int i=0;i<32;i++) key[i]=(uint8_t)(i*2+1);
        aes256_ctx ac; aes256_init(&ac, key);
        fails += test_gcm_roundtrip("AES-256-GCM", aes_blk, &ac);
        serpent_ctx sc; serpent_setkey(&sc, key, 32);
        fails += test_gcm_roundtrip("Serpent-256-GCM", serpent_blk, &sc);
        twofish_ctx tc; twofish_setkey(&tc, key);
        fails += test_gcm_roundtrip("Twofish-256-GCM", twofish_blk, &tc);
    }
    fails += test_xchacha_roundtrip();
    fails += test_xchacha_kat();
    fails += test_argon2();

    if (fails) { fprintf(stderr, "\n%d test(s) FAILED\n", fails); return 1; }
    fprintf(stderr, "\nAll self-tests passed.\n");
    return 0;
}
