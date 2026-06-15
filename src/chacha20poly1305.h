/* XChaCha20-Poly1305 AEAD (RFC 8439 + draft-irtf-cfrg-xchacha).
 * Compact public-domain style implementation. */
#ifndef MC_CHACHA20POLY1305_H
#define MC_CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define XCHACHA20POLY1305_KEYBYTES   32
#define XCHACHA20POLY1305_NONCEBYTES 24
#define XCHACHA20POLY1305_TAGBYTES   16

/* Encrypt: writes ciphertext (same length as plaintext) and a 16-byte tag. */
void xchacha20poly1305_encrypt(uint8_t *ct, uint8_t tag[16],
                               const uint8_t *pt, size_t ptlen,
                               const uint8_t *aad, size_t aadlen,
                               const uint8_t nonce[24], const uint8_t key[32]);

/* Decrypt: verifies tag in constant time. Returns 0 on success, -1 on auth fail. */
int xchacha20poly1305_decrypt(uint8_t *pt,
                              const uint8_t *ct, size_t ctlen,
                              const uint8_t tag[16],
                              const uint8_t *aad, size_t aadlen,
                              const uint8_t nonce[24], const uint8_t key[32]);

#endif
