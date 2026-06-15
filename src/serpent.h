/* Serpent block cipher (128-bit block, up to 256-bit key), encryption only.
 * Algorithm by Anderson, Biham & Knudsen; S-box boolean equations by
 * Dag Arne Osvik. Forward direction is all that GCM requires. */
#ifndef MC_SERPENT_H
#define MC_SERPENT_H

#include <stdint.h>

#define SERPENT_EXPKEY_WORDS 132

typedef struct { uint32_t expkey[SERPENT_EXPKEY_WORDS]; } serpent_ctx;

/* keylen in bytes, 1..32 (we use 32). */
void serpent_setkey(serpent_ctx *ctx, const uint8_t *key, unsigned keylen);
void serpent_encrypt_block(const serpent_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

#endif
