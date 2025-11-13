#pragma once
/**
 * @file ascon_iface.h
 * @brief Thin, well-documented wrapper to use ASCON-128a AEAD for PSK channels.
 *
 * This module hides:
 *  - Key normalization (handle 16B / 32B / short PSKs with Meshtastic-style padding).
 *  - Nonce expansion: Meshtastic produces a 13-byte nonce; ASCON needs 16 bytes.
 *  - Direct calls into your ASCON AEAD C implementation (crypto_aead_encrypt/decrypt).
 *
 * Both functions are IN-PLACE: they read plaintext/ciphertext from `buf_inplace`
 * and write the result back to the same pointer.
 *
 * Lengths:
 *  - Encrypt:  *io_len (in)  = plaintext length
 * 
 *              *io_len (out) = ciphertext length (plaintext + 16-byte tag)
 *  - Decrypt:  *io_len (in)  = ciphertext length (must be >= 16)
 *              *io_len (out) = plaintext length (ciphertext - 16)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Encrypt in-place using ASCON-128a AEAD.
 *
 * @param buf_inplace  Buffer holding the plaintext; will be overwritten with ciphertext||tag.
 * @param io_len       IN: plaintext length; OUT: ciphertext length (= in + 16).
 * @param psk          Channel PSK (raw user-provided key material).
 * @param psk_len      Length of PSK in bytes (can be 16, 32, or short).
 * @param nonce13      13-byte Meshtastic nonce (initNonce output).
 * @param nonce13_len  Must be 13; extra bytes are ignored, fewer bytes fail.
 * @return true on success, false on error.
 */
bool ascon_psk_encrypt(uint8_t* buf_inplace, size_t* io_len,
                       const uint8_t* psk, size_t psk_len,
                       const uint8_t* nonce13, size_t nonce13_len);

/**
 * @brief Decrypt in-place using ASCON-128a AEAD.
 *
 * @param buf_inplace  Buffer holding the ciphertext||tag; will be overwritten with plaintext.
 * @param io_len       IN: ciphertext length (must be >= 16); OUT: plaintext length (= in - 16).
 * @param psk          Channel PSK (raw user-provided key material).
 * @param psk_len      Length of PSK in bytes (can be 16, 32, or short).
 * @param nonce13      13-byte Meshtastic nonce (initNonce output).
 * @param nonce13_len  Must be 13; extra bytes are ignored, fewer bytes fail.
 * @return true on success (valid tag), false on error (bad inputs or tag verification failed).
 */
bool ascon_psk_decrypt(uint8_t* buf_inplace, size_t* io_len,
                       const uint8_t* psk, size_t psk_len,
                       const uint8_t* nonce13, size_t nonce13_len);
