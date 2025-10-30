#include "CryptoEngine.h"
#include "configuration.h"
#include "crypto/ascon/ascon_iface.h"   // <- incluye nuestro placeholder
#include <cstring>

class ESP32CryptoEngineAscon : public CryptoEngine {
public:
    ESP32CryptoEngineAscon() {}  // sin logs en el ctor

    void encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes) override
    {
        // Si no hay clave => sin cifrado (igual que el engine base)
        if (key.length <= 0 || bytes == nullptr || numBytes == 0) return;

        // Construye el nonce del paquete (igual que el base)
        initNonce(fromNode, packetId);

        // Por ahora usamos nuestro “ASCON-CTR placeholder”
        // Mantiene longitudes 1:1 (como CTR), perfecto para canal PSK.
        LOG_INFO("[ASCON] PSK detectado -> using ascon_ctr_xor()");
        if (numBytes > MAX_BLOCKSIZE) {
            LOG_ERROR("[ASCON] Packet too large: %u (max=%u). noop!", (unsigned)numBytes, (unsigned)MAX_BLOCKSIZE);
            return;
        }
        ascon_ctr_xor(bytes, numBytes, key.bytes, (size_t)key.length, nonce, sizeof(nonce));
    }

    void decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes) override
    {
        // Simétrico: mismo proceso que encrypt
        if (key.length <= 0 || bytes == nullptr || numBytes == 0) return;

        initNonce(fromNode, packetId);
        LOG_INFO("[ASCON] PSK detectado -> using ascon_ctr_xor() [decrypt]");
        if (numBytes > MAX_BLOCKSIZE) {
            LOG_ERROR("[ASCON] Packet too large (decrypt): %u (max=%u). noop!", (unsigned)numBytes, (unsigned)MAX_BLOCKSIZE);
            return;
        }
        ascon_ctr_xor(bytes, numBytes, key.bytes, (size_t)key.length, nonce, sizeof(nonce));
    }
};

#ifdef USE_ASCON_ENGINE
CryptoEngine *crypto = new ESP32CryptoEngineAscon();
#endif
