#include "CryptoEngine.h"
#include "configuration.h"
#include "crypto/ascon/ascon_iface.h"
#include <cstring>

/**
 * @brief Crypto engine for ESP32 that routes PSK channels to ASCON-128a AEAD.
 *
 * Design:
 *  - Public / non-PSK channels still use the base AES-CTR implementation.
 *  - PKI / Curve25519 + AES-CCM is untouched (handled outside this class).
 *  - Only private PSK channels (marked via setUseAscon(true)) use ASCON-128a AEAD.
 */
class ESP32CryptoEngineAscon : public CryptoEngine {
public:
    ESP32CryptoEngineAscon() {}

    /**
     * @brief Encrypt a packet in-place.
     *
     * If use_ascon_for_this_packet == false:
     *   - Delegate to the base AES-CTR implementation (CryptoEngine::encryptPacket).
     *
     * If use_ascon_for_this_packet == true:
     *   - Use ASCON-128a AEAD over the PSK:
     *       * Plaintext read from `bytes[0..numBytes-1]`.
     *       * Ciphertext || 16B tag written back to `bytes[...]`.
     *       * `numBytes` is updated to ciphertext length (plaintext + 16).
     */
    void encryptPacket(uint32_t fromNode, uint64_t packetId, size_t &numBytes, uint8_t *bytes) override
    {
        // No key or invalid buffer → nothing to do.
        if (key.length <= 0 || !bytes || numBytes == 0) {
            return;
        }

        // If this packet is NOT marked as “use ASCON”, fallback to the default AES-CTR behavior.
        if (!use_ascon_for_this_packet) {
            LOG_DEBUG("[ASCON] use_ascon_for_this_packet == false → fallback to AES-CTR engine");
            CryptoEngine::encryptPacket(fromNode, packetId, numBytes, bytes);
            return;
        }

        // --- ASCON path (private PSK channel) ---------------------------------
        if (numBytes > MAX_BLOCKSIZE) {
            LOG_ERROR("[ASCON-AEAD] Packet too large for engine: %u (max=%u). noop!",
                      (unsigned)numBytes, (unsigned)MAX_BLOCKSIZE);
            return;
        }

        // Build the standard 16-byte nonce used by Meshtastic.
        // The wrapper will only consume the first 13 bytes and expand them to 16.
        initNonce(fromNode, packetId);

        // For debug / thesis logs: capture initial length.
        const size_t plain_len = numBytes;

        LOG_INFO("[ASCON-AEAD] encrypt: from=0x%08x id=0x%08x plain_len=%u",
                 (unsigned)fromNode, (unsigned)packetId, (unsigned)plain_len);

        // ASCON-128a AEAD in-place:
        //  - IN:  numBytes = plaintext length.
        //  - OUT: numBytes = ciphertext length (plaintext + 16-byte tag).
        bool ok = ascon_psk_encrypt(
            /*buf_inplace*/ bytes,
            /*io_len    */ &numBytes,
            /*psk       */ key.bytes,
            /*psk_len   */ (size_t)key.length,
            /*nonce13   */ nonce,       // first 13 bytes are used
            /*nonce13len*/ 13);

        if (!ok) {
            LOG_ERROR("[ASCON-AEAD] encrypt FAILED (psk/nonce error?) → leaving buffer unchanged");
            // On failure we keep numBytes as the original plaintext length.
            numBytes = plain_len;
            return;
        }

        const size_t cipher_len = numBytes;
        LOG_INFO("[ASCON-AEAD] encrypt: cipher_len=%u (tag included, +%u bytes)",
                 (unsigned)cipher_len,
                 (unsigned)(cipher_len - plain_len));
    }

    // decrypt(...) lo dejaremos para el siguiente paso (PASO 2),
    // donde conectaremos ascon_psk_decrypt y ajustaremos rawSize.
    void decrypt(uint32_t fromNode, uint64_t packetId, size_t &numBytes, uint8_t *bytes) override
    {
        // De momento, mantenemos el comportamiento anterior (placeholder).
        // En el PASO 2 implementaremos la llamada real a ascon_psk_decrypt(...)
        // y la gestión de numBytes (cipher_len → plain_len).
        if (key.length <= 0 || !bytes || numBytes == 0) {
            return;
        }

        if (!use_ascon_for_this_packet) {
            LOG_DEBUG("[ASCON] decrypt fallback to AES-CTR engine");
            CryptoEngine::decrypt(fromNode, packetId, numBytes, bytes);
            return;
        }

        // Placeholder: por ahora solo logueamos que se ha llamado.
        // En el siguiente paso esto será reemplazado por ASCON-AEAD real.
        LOG_WARN("[ASCON-AEAD] decrypt() placeholder called. Implementation will be added in PASO 2.");
    }
};

#ifdef USE_ASCON_ENGINE
CryptoEngine *crypto = new ESP32CryptoEngineAscon();
#endif
