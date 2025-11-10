#include "ascon_iface.h"

extern "C" {
#include "ascon.h"         // ascon_state_t
#include "constants.h"     // ASCON_128A_IV, ASCON_128A_RATE
#include "permutations.h"  // P12, P8
#include "word.h"          // LOADBYTES, STOREBYTES
#include "api.h"           // CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES   ⬅⬅⬅ AÑADIR ESTO
}

#include <string.h>
#include <stdint.h>
/**
 * ascon_ctr_xor:
 *
 *  - data: buffer a cifrar/descifrar in-place
 *  - len: longitud del buffer
 *  - key: clave de canal (PSK) – usaremos los primeros 16 bytes
 *  - keylen: longitud real de la clave
 *  - nonce: nonce/IV (Meshtastic lo genera con fromNode+packetId)
 *  - noncelen: longitud real del nonce
 *
 * Usamos el núcleo de ASCON-128a para generar un keystream de 16 bytes
 * por iteración (ASCON_128A_RATE) y lo XOReamos con data.
 *
 * No añadimos tag, no cambiamos el tamaño del mensaje.
 */
void ascon_ctr_xor(uint8_t* data, size_t len,
                   const uint8_t* key, size_t keylen,
                   const uint8_t* nonce, size_t noncelen)
{
    if (!data || !key || !nonce || len == 0)
        return;

    // Ascon-128a usa clave de 16 bytes y nonce de 16 bytes (api.h)
if (keylen < CRYPTO_KEYBYTES || noncelen < CRYPTO_NPUBBYTES) {
    // Clave/nonce demasiado cortos → mejor no hacer nada
    return;
}


    // Cargar K0,K1 y N0,N1 desde los primeros 16 bytes de key y nonce
    const uint64_t K0 = LOADBYTES(key, 8);
    const uint64_t K1 = LOADBYTES(key + 8, 8);
    const uint64_t N0 = LOADBYTES(nonce, 8);
    const uint64_t N1 = LOADBYTES(nonce + 8, 8);

    // Inicializar el estado como en crypto_aead_encrypt (aead.c)
    ascon_state_t s;
    s.x[0] = ASCON_128A_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;

    // Primera permutación con la clave
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    // Ahora usamos el estado como un generador de keystream.
    size_t offset = 0;
    while (offset < len) {
        // Sacamos un bloque de keystream de 16 bytes (ASCON_128A_RATE)
        uint8_t ks[ASCON_128A_RATE];
        STOREBYTES(ks,     s.x[0], 8);
        STOREBYTES(ks + 8, s.x[1], 8);

        size_t chunk = len - offset;
        if (chunk > ASCON_128A_RATE)
            chunk = ASCON_128A_RATE;

        // XOReamos este bloque de keystream con el payload
        for (size_t i = 0; i < chunk; ++i) {
            data[offset + i] ^= ks[i];
        }

        offset += chunk;

        // Avanzamos el estado para el siguiente bloque de keystream
        P8(&s);
    }
}
