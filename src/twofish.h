/* Twofish block cipher (128-bit block, 256-bit key), encryption only.
 * Algorithm by Schneier, Kelsey, Whiting, Wagner, Hall & Ferguson;
 * released into the public domain. Forward direction is all GCM requires. */
#ifndef MC_TWOFISH_H
#define MC_TWOFISH_H

#include <stdint.h>

typedef struct {
    uint32_t K[40];  /* whitening + round subkeys */
    uint32_t S[4];   /* key-dependent S-box words (reversed RS output) */
} twofish_ctx;

/* key must be 32 bytes (256-bit). */
void twofish_setkey(twofish_ctx *ctx, const uint8_t key[32]);
void twofish_encrypt_block(const twofish_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

#endif
