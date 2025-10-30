#include "ascon_iface.h"
#include <string.h>
#include <SHA256.h>  // disponible en el proyecto (ya lo usan en CryptoEngine)

static void keystream_block(uint8_t out[32],
                            const uint8_t* key, size_t keylen,
                            const uint8_t* nonce, size_t noncelen,
                            uint32_t counter)
{
    SHA256 h;
    h.reset();
    h.update(key,   keylen);
    h.update(nonce, noncelen);
    // counter en little-endian
    uint8_t ctr[4] = {
        (uint8_t)(counter & 0xFF),
        (uint8_t)((counter >> 8) & 0xFF),
        (uint8_t)((counter >> 16) & 0xFF),
        (uint8_t)((counter >> 24) & 0xFF)
    };
    h.update(ctr, sizeof(ctr));
    h.finalize(out, 32);
}

void ascon_ctr_xor(uint8_t* data, size_t len,
                   const uint8_t* key, size_t keylen,
                   const uint8_t* nonce, size_t noncelen)
{
    if (!data || !key || !nonce || keylen == 0 || noncelen == 0 || len == 0) return;

    uint32_t ctr = 0;
    size_t done = 0;
    uint8_t ks[32];

    while (done < len) {
        keystream_block(ks, key, keylen, nonce, noncelen, ctr++);
        size_t take = (len - done > sizeof(ks)) ? sizeof(ks) : (len - done);
        for (size_t i = 0; i < take; ++i) {
            data[done + i] ^= ks[i];
        }
        done += take;
    }
}
