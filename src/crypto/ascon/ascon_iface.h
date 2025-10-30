#pragma once
#include <stdint.h>
#include <stddef.h>

/**
 * Placeholder de “ASCON-CTR” para laboratorio:
 * - Genera un keystream determinístico a partir de (key || nonce || counter)
 *   usando SHA-256 por bloques y hace XOR con los datos.
 * - Simétrico: llamar la misma función en “encrypt” y “decrypt”.
 * - No es cripto real, es sólo para validar el hook en el engine.
 */
void ascon_ctr_xor(uint8_t* data, size_t len,
                   const uint8_t* key, size_t keylen,
                   const uint8_t* nonce, size_t noncelen);
