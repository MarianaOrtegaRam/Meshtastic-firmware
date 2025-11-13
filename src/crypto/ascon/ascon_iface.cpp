/**
 * @file ascon_iface.cpp
 * @brief Implementation of a minimal, readable wrapper for ASCON-128a AEAD.
 *
 * Design notes:
 * - We accept PSKs of length 16, 32, or "short". Meshtastic today pads short PSKs.
 *   We replicate that convention and then:
 *     * if 16 bytes: use as is;
 *     * if 32 bytes: derive K16 = SHA-256(PSK32)[0..15];
 *     * if short: pad to 16 (zeros) as Meshtastic already does and use 16 bytes.
 * - Nonce: Meshtastic generates a 13-byte nonce (initNonce). ASCON requires 16 bytes.
 *   We derive N16 = SHA-256( channel_hint || nonce13 )[0..15].
 *   The channel_hint is a single byte you may later set to the channel hash LSB.
 *   For now we use 0x00 to avoid changing upstream call signatures.
 *
 * - Associated Data (AD): none for now (ad = nullptr, adlen = 0).
 *   Later we can pass the channel hash as AD without changing frame sizes.
 */

#include "ascon_iface.h"

extern "C" {
  #include "api.h"           // CRYPTO_* sizes, ASCON_AEAD_RATE, etc.
  #include "crypto_aead.h"   // crypto_aead_encrypt/decrypt
}

#include <string.h>
#include <stdint.h>
#include "mbedtls/sha256.h"

// ---------- Helpers ---------------------------------------------------------

/**
 * @brief Normalize a PSK into a 16-byte ASCON key (K).
 *
 * Rules:
 *  - 16 bytes  -> copy as is.
 *  - 32 bytes  -> K = SHA-256(PSK32)[0..15].
 *  - otherwise -> pad with zeros to 16 and use those 16 bytes.
 */
static void kdf_psk16(uint8_t out16[16], const uint8_t* psk, size_t psk_len) {
  if (!psk) { memset(out16, 0, 16); return; }

  if (psk_len == 16) {
    memcpy(out16, psk, 16);
    return;
  }

  if (psk_len >= 32) {
    uint8_t dig[32];
    mbedtls_sha256(psk, 32, dig, 0);
    memcpy(out16, dig, 16);
    return;
  }

  // "Short" keys: Meshtastic pads with zeros. We mimic that to be consistent.
  uint8_t tmp[16] = {0};
  if (psk_len > 0) {
    size_t n = (psk_len > 16 ? 16 : psk_len);
    memcpy(tmp, psk, n);
  }
  memcpy(out16, tmp, 16);
}

/**
 * @brief Expand a 13-byte Meshtastic nonce into a 16-byte nonce for ASCON.
 *
 * We compute N16 = SHA-256( channel_hint (1B) || nonce13 )[0..15].
 * This keeps both sides deterministic without changing packet headers.
 */
static void derive_nonce16(uint8_t out16[16],
                           const uint8_t* nonce13, size_t nonce13_len,
                           uint8_t channel_hint /* e.g., channel hash LSB */) {
  uint8_t in[1 + 13] = {0};
  in[0] = channel_hint;
  size_t n = (nonce13_len > 13 ? 13 : nonce13_len);
  if (nonce13 && n > 0) memcpy(in + 1, nonce13, n);

  uint8_t dig[32];
  mbedtls_sha256(in, 1 + n, dig, 0);
  memcpy(out16, dig, 16);
}

// ---------- Public API ------------------------------------------------------

bool ascon_psk_encrypt(uint8_t* buf, size_t* io_len,
                       const uint8_t* psk, size_t psk_len,
                       const uint8_t* nonce13, size_t nonce13_len) {
  if (!buf || !io_len || !psk || !nonce13) return false;
  if (nonce13_len < 13) return false;          // must be at least 13
  if (*io_len == 0) return true;               // nothing to encrypt

  uint8_t K[16], N[16];
  kdf_psk16(K, psk, psk_len);
  derive_nonce16(N, nonce13, nonce13_len, /*channel_hint*/ 0x00);

  unsigned long long clen = 0ULL;
  int rc = crypto_aead_encrypt(
              /*c   */ buf,
              /*clen*/ &clen,
              /*m   */ buf,
              /*mlen*/ (unsigned long long)(*io_len),
              /*ad  */ nullptr,
              /*adln*/ 0ULL,
              /*nsec*/ nullptr,
              /*npub*/ N,
              /*k   */ K);

  if (rc != 0) return false;

  *io_len = (size_t)clen; // plaintext + 16-byte tag
  return true;
}

bool ascon_psk_decrypt(uint8_t* buf, size_t* io_len,
                       const uint8_t* psk, size_t psk_len,
                       const uint8_t* nonce13, size_t nonce13_len) {
  if (!buf || !io_len || !psk || !nonce13) return false;
  if (*io_len < 16) return false;              // must at least hold the tag
  if (nonce13_len < 13) return false;

  uint8_t K[16], N[16];
  kdf_psk16(K, psk, psk_len);
  derive_nonce16(N, nonce13, nonce13_len, /*channel_hint*/ 0x00);

  unsigned long long mlen = 0ULL;
  int rc = crypto_aead_decrypt(
              /*m    */ buf,
              /*mlen */ &mlen,
              /*nsec */ nullptr,
              /*c    */ buf,
              /*clen */ (unsigned long long)(*io_len),
              /*ad   */ nullptr,
              /*adlen*/ 0ULL,
              /*npub */ N,
              /*k    */ K);

  if (rc != 0) {
    // Authentication failed (tag mismatch) or bad inputs
    return false;
  }

  *io_len = (size_t)mlen; // ciphertext - 16-byte tag
  return true;
}
