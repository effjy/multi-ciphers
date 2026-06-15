/* AES-256 block encryption (forward direction only - sufficient for GCM/CTR).
 * Compact public-domain style implementation. */
#ifndef MC_AES_H
#define MC_AES_H

#include <stdint.h>

typedef struct { uint8_t round_keys[240]; } aes256_ctx; /* 15 round keys * 16 */

void aes256_init(aes256_ctx *ctx, const uint8_t key[32]);
void aes256_encrypt_block(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

#endif
