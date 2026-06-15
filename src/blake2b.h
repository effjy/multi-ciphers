/* BLAKE2b - compact implementation (public domain, RFC 7693 based).
 * Used internally by the bundled Argon2id implementation. */
#ifndef MC_BLAKE2B_H
#define MC_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_BLOCKBYTES 128

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
} blake2b_state;

int  blake2b_init(blake2b_state *S, size_t outlen);
int  blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen);
void blake2b_update(blake2b_state *S, const void *in, size_t inlen);
void blake2b_final(blake2b_state *S, void *out, size_t outlen);

/* one-shot */
int  blake2b(void *out, size_t outlen, const void *in, size_t inlen,
             const void *key, size_t keylen);

#endif
