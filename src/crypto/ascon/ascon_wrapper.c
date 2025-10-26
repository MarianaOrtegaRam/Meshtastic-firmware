#include "ascon_wrapper.h"
#include "crypto_aead.h" // tu implementación ASCON: aead.c / crypto_aead.h
#include <string.h>

void ascon_key_from_shared_truncate(const uint8_t shared32[32], uint8_t out16[16]) {
    memcpy(out16, shared32, 16);
}

int ascon_encrypt(
  const uint8_t key16[ASCON_KEYLEN],
  const uint8_t nonce16[ASCON_NONCELEN],
  const uint8_t *ad, size_t adlen,
  const uint8_t *pt, size_t ptlen,
  uint8_t *ct, size_t *ctlen_out)
{
  unsigned long long clen = 0;
  int rc = crypto_aead_encrypt(ct, &clen,
                               pt, (unsigned long long)ptlen,
                               ad, (unsigned long long)adlen,
                               NULL,
                               nonce16,
                               key16);
  if (rc != 0) return rc;
  *ctlen_out = (size_t)clen; // ptlen + 16
  return 0;
}

int ascon_decrypt(
  const uint8_t key16[ASCON_KEYLEN],
  const uint8_t nonce16[ASCON_NONCELEN],
  const uint8_t *ad, size_t adlen,
  const uint8_t *ct, size_t ctlen,
  uint8_t *pt, size_t *ptlen_out)
{
  unsigned long long mlen = 0;
  int rc = crypto_aead_decrypt(pt, &mlen, NULL,
                               ct, (unsigned long long)ctlen,
                               ad, (unsigned long long)adlen,
                               nonce16,
                               key16);
  if (rc != 0) return rc;
  *ptlen_out = (size_t)mlen; // ctlen - 16
  return 0;
}
