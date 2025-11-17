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

    /**
     * @brief Decrypt a mesh packet using ASCON-128a AEAD for PSK channels.
     *
     * This function is called by Router::perhapsDecode() for channel-based
     * encryption (PSK). Curve25519 / PKI decryption still uses
     * CryptoEngine::decryptCurve25519() and is NOT affected.
     *
     * Parameters:
     *  - fromNode: MeshPacket.from field (32-bit node id of sender).
     *  - packetId: MeshPacket.id field (64-bit packet sequence).
     *  - numBytes: Number of bytes currently stored in `bytes`.
     *              For ASCON this is: ciphertext_len = plaintext_len + 16(tag).
     *  - bytes:    In-place buffer holding ciphertext||tag, will be overwritten
     *              with the recovered plaintext on successful decryption.
     *
     * Lengths:
     *  - Input : numBytes = clen = mlen + 16.
     *  - Output: The first (numBytes - 16) bytes of `bytes` contain the
     *            plaintext. We DO NOT modify `numBytes` here because the
     *            Router is responsible for stripping the 16-byte tag before
     *            calling pb_decode_from_bytes().
     */
    void decrypt(uint32_t fromNode, uint64_t packetId, size_t &numBytes, uint8_t *bytes) override
    {
        // No key / no data => nothing to do (same behavior as base engine).
        if (key.length <= 0 || bytes == nullptr || numBytes == 0) {
            return;
        }

        // For now we only decrypt PSK channels with ASCON.
        // PKI traffic uses decryptCurve25519() and never calls this method.
        // If for some reason this flag is false, we leave the buffer as-is.
        if (!use_ascon_for_this_packet) {
            LOG_DEBUG("[ASCON-AEAD] decrypt(): use_ascon_for_this_packet=false → noop");
            return;
        }

        // Build the 13-byte Meshtastic nonce (same as in encryptPacket).
        initNonce(fromNode, packetId);  // fills `nonce` member in CryptoEngine

        // Ciphertext length (includes 16-byte tag).
        size_t clen = numBytes;

        // Call the ASCON-128a AEAD wrapper. It will:
        //  - derive a 16-byte key from the PSK (16/32/short),
        //  - expand the 13-byte nonce to 16 bytes with SHA-256,
        //  - verify the tag,
        //  - and, on success, overwrite `bytes[0..mlen-1]` with plaintext.
        bool ok = ascon_psk_decrypt(
            bytes,                 // in-place buffer: ciphertext||tag → plaintext
            &clen,                 // IN: clen, OUT: mlen = clen - 16
            key.bytes,             // PSK bytes
            static_cast<size_t>(key.length),
            nonce,                 // 13-byte nonce produced by initNonce()
            sizeof(nonce)          // should be 13
        );

        if (!ok) {
            // Authentication failed or inputs invalid: wipe buffer and log.
            LOG_WARN("[ASCON-AEAD] dec: clen=%u tag_ok=0 → dropping packet",
                     (unsigned)numBytes);
            memset(bytes, 0, numBytes);
            // Router will fail protobuf decoding and treat this as a bad PSK.
            return;
        }

        // Successful ASCON-128a decryption.
        // `clen` now holds mlen (plaintext length), but Router still tracks
        // the original numBytes. Router::perhapsDecode() will subtract the
        // 16-byte tag when calling pb_decode_from_bytes().
        LOG_INFO("[ASCON-AEAD] dec: clen=%u mlen=%u tag_ok=1",
                 (unsigned)numBytes,
                 (unsigned)clen);
    }
};

#ifdef USE_ASCON_ENGINE
CryptoEngine *crypto = new ESP32CryptoEngineAscon();
#endif
