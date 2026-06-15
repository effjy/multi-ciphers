/* Argon2id - compact implementation of the PHC password-hashing winner.
 * Reference: https://github.com/P-H-C/phc-winner-argon2 (CC0 / Apache-2.0).
 * Only the Argon2id variant, v1.3 (0x13), single-process, is provided. */
#ifndef MC_ARGON2_H
#define MC_ARGON2_H

#include <stddef.h>
#include <stdint.h>

/* Derive `outlen` key bytes from a password.
 *   t_cost  : number of passes      (>= 1)
 *   m_cost  : memory in KiB         (>= 8 * lanes)
 *   lanes   : parallelism / lanes   (>= 1)
 * Returns 0 on success, negative on error (bad params / allocation failure). */
int argon2id_hash(void *out, size_t outlen,
                  const void *pwd, size_t pwdlen,
                  const void *salt, size_t saltlen,
                  uint32_t t_cost, uint32_t m_cost, uint32_t lanes);

#endif
