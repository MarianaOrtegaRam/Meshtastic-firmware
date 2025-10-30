#include "CryptoEngine.h"
#include "configuration.h"

class ESP32CryptoEngineAscon : public CryptoEngine
{
  public:
    ESP32CryptoEngineAscon() {}  // sin logs en constructor

    void encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes) override
    {
        LOG_DEBUG("[ASCON] encryptPacket() placeholder, len=%u", (unsigned)numBytes);
        // TODO: cuando integremos ASCON real, reemplazar esta línea:
        CryptoEngine::encryptPacket(fromNode, packetId, numBytes, bytes);  // delega a AES-CTR por ahora
    }

    void decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes) override
    {
        LOG_DEBUG("[ASCON] decrypt() placeholder, len=%u", (unsigned)numBytes);
        // TODO: cuando integremos ASCON real, reemplazar esta línea:
        CryptoEngine::decrypt(fromNode, packetId, numBytes, bytes);        // delega a AES-CTR por ahora
    }
};

// Solo instanciamos el motor ASCON si está definido el flag de compilación
#ifdef USE_ASCON_ENGINE
CryptoEngine *crypto = new ESP32CryptoEngineAscon();
#endif
