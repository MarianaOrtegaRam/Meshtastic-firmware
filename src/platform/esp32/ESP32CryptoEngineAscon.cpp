#include "CryptoEngine.h"
#include "configuration.h"

class ESP32CryptoEngineAscon : public CryptoEngine
{
public:
    ESP32CryptoEngineAscon() { LOG_INFO("✅ ESP32CryptoEngineAscon initialized (test mode)"); }

    void encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes) override {
        LOG_INFO("🟢 encryptPacket() [ASCON placeholder]");
        // Aquí después llamaremos a tu ascon_encrypt(...)
    }

    void decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes) override {
        LOG_INFO("🟠 decrypt() [ASCON placeholder]");
        // Aquí después llamaremos a tu ascon_decrypt(...)
    }
};

#ifdef USE_ASCON_ENGINE
CryptoEngine *crypto = new ESP32CryptoEngineAscon();
#endif
