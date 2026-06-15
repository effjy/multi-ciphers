#ifndef MC_RANDOM_H
#define MC_RANDOM_H
#include <stddef.h>
/* Fill buf with cryptographically secure random bytes. Returns 0 on success. */
int mc_random_bytes(void *buf, size_t len);
#endif
