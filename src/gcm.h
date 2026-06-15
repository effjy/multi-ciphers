/* Generic GCM (Galois/Counter Mode) over any 128-bit block cipher.
 * Works with a 96-bit (12-byte) nonce, producing a 16-byte tag. */
#ifndef MC_GCM_H
#define MC_GCM_H

#include <stddef.h>
#include <stdint.h>

typedef void (*gcm_block_fn)(const void *cipher_ctx, const uint8_t in[16], uint8_t out[16]);

void gcm_encrypt(gcm_block_fn enc, const void *cipher_ctx,
                 const uint8_t nonce[12],
                 const uint8_t *aad, size_t aadlen,
                 const uint8_t *pt, size_t ptlen,
                 uint8_t *ct, uint8_t tag[16]);

/* Returns 0 on success, -1 on authentication failure. */
int gcm_decrypt(gcm_block_fn enc, const void *cipher_ctx,
                const uint8_t nonce[12],
                const uint8_t *aad, size_t aadlen,
                const uint8_t *ct, size_t ctlen,
                const uint8_t tag[16], uint8_t *pt);

#endif
