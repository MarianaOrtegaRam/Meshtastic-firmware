#ifndef ASCON_WRAPPER_H
#define ASCON_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_KEYLEN 16
#define ASCON_NONCELEN 16
#define ASCON_TAGLEN 16

void ascon_key_from_shared_truncate(const uint8_t shared32[32], uint8_t out16[16]);

int ascon_encrypt(
  const uint8_t key16[ASCON_KEYLEN],
  const uint8_t nonce16[ASCON_NONCELEN],
  const uint8_t *ad, size_t adlen,
  const uint8_t *pt, size_t ptlen,
  uint8_t *ct, size_t *ctlen_out);

int ascon_decrypt(
  const uint8_t key16[ASCON_KEYLEN],
  const uint8_t nonce16[ASCON_NONCELEN],
  const uint8_t *ad, size_t adlen,
  const uint8_t *ct, size_t ctlen,
  uint8_t *pt, size_t *ptlen_out);

#ifdef __cplusplus
}
#endif

#endif // ASCON_WRAPPER_H
