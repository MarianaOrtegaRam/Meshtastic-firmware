#include "CryptoEngine.h"
// #include "NodeDB.h"
#include "architecture.h"

#if !(MESHTASTIC_EXCLUDE_PKI)
#include "NodeDB.h"
#include "aes-ccm.h"
#include "meshUtils.h"
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <SHA256.h>

#ifdef ENABLE_ASCON
// Include your ASCON wrapper in C linkage so we can call it from C++
extern "C" {
  #include "ascon/ascon_wrapper.h"
}
#endif

#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
#if !defined(ARCH_STM32WL)
#define CryptRNG RNG
#endif

/**
 * Create a public/private key pair with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The destination for the private key.
 */
void CryptoEngine::generateKeyPair(uint8_t *pubKey, uint8_t *privKey)
{
    // Mix in any randomness we can, to make key generation stronger.
    CryptRNG.begin(optstr(APP_VERSION));
    if (myNodeInfo.device_id.size == 16) {
        CryptRNG.stir(myNodeInfo.device_id.bytes, myNodeInfo.device_id.size);
    }
    auto noise = random();
    CryptRNG.stir((uint8_t *)&noise, sizeof(noise));

    LOG_DEBUG("Generate Curve25519 keypair");
    Curve25519::dh1(public_key, private_key);
    memcpy(pubKey, public_key, sizeof(public_key));
    memcpy(privKey, private_key, sizeof(private_key));
}

/**
 * regenerate a public key with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The source for the private key.
 */
bool CryptoEngine::regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey)
{
    if (!memfll(privKey, 0, sizeof(private_key))) {
        Curve25519::eval(pubKey, privKey, 0);
        if (Curve25519::isWeakPoint(pubKey)) {
            LOG_ERROR("PKI key generation failed. Specified private key results in a weak");
            memset(pubKey, 0, 32);
            return false;
        }
        memcpy(private_key, privKey, sizeof(private_key));
        memcpy(public_key, pubKey, sizeof(public_key));
    } else {
        LOG_WARN("X25519 key generation failed due to blank private key");
        return false;
    }
    return true;
}
#endif

void CryptoEngine::clearKeys()
{
    memset(public_key, 0, sizeof(public_key));
    memset(private_key, 0, sizeof(private_key));
}

/**
 * Encrypt a packet's payload using a key generated with Curve25519 and SHA256
 * for a specific node.
 *
 * Note: This function previously used AES-CCM (aes_ccm_ae). When ENABLE_ASCON
 * is defined we use ASCON AEAD. The ASCON on-wire layout used here is:
 *
 *   [ciphertext || ascon_tag(16)] [extraNonce(4)]
 *
 * That means the receiver must subtract 20 bytes total (tag+extraNonce).
 *
 * @param toNode The MeshPacket `to` field.
 * @param fromNode The MeshPacket `from` field.
 * @param remotePublic The remote node's Curve25519 public key.
 * @param packetNum The MeshPacket `id` field.
 * @param numBytes Number of bytes of plaintext in the bytes buffer.
 * @param bytes Buffer containing plaintext input.
 * @param bytesOut Output buffer to be populated with encrypted ciphertext.
 */
bool CryptoEngine::encryptCurve25519(uint32_t toNode, uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic,
                                     uint64_t packetNum, size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut)
{
    uint32_t extraNonceTmp = (uint32_t)random();

    if (remotePublic.size == 0) {
        LOG_DEBUG("Node %d or their public_key not found", toNode);
        return false;
    }

    // Compute DH shared secret into shared_key
    if (!crypto->setDHPublicKey(remotePublic.bytes)) {
        return false;
    }
    // Hash the shared secret into shared_key (32 bytes) - same as existing code flow
    crypto->hash(shared_key, 32);

    // Build nonce: packetNum (8) | fromNode (4) | extraNonce (4)
    initNonce(fromNode, packetNum, extraNonceTmp);

#ifdef ENABLE_ASCON
    // Derive 16-byte key for ASCON (wrapper helper)
    uint8_t ascon_key[ASCON_KEYLEN];
    ascon_key_from_shared_truncate(shared_key, ascon_key);

    // Encrypt: write ciphertext+tag directly into bytesOut
    size_t ctlen = 0;
    int r = ascon_encrypt(ascon_key, nonce, nullptr, 0, bytes, numBytes, bytesOut, &ctlen);
    if (r != 0) {
        LOG_WARN("ASCON encrypt failed (code %d)", r);
        return false;
    }

    // Append 4-byte extraNonce (little-endian) after ciphertext+tag
    memcpy(bytesOut + ctlen, &extraNonceTmp, sizeof(extraNonceTmp));
    // final on-wire length is ctlen + 4
    return true;
#else
    // Legacy AES-CCM path (keeps old behavior)
    uint8_t auth[12]; // previous code used 12 bytes total: 8 tag + 4 extraNonce
    // copy plaintext into bytesOut
    memcpy(bytesOut, bytes, numBytes);
    aes_ccm_ae(shared_key, 32, nonce, 8, bytesOut, numBytes, nullptr, 0, bytesOut, auth);
    // write auth (8 bytes tag + 4 bytes extraNonce)
    memcpy(bytesOut + numBytes, auth, 12);
    memcpy(bytesOut + numBytes + 8, &extraNonceTmp, sizeof(extraNonceTmp));
    return true;
#endif
}

/**
 * Decrypt a packet's payload using a key generated with Curve25519 and SHA256
 * for a specific node.
 *
 * Note: When ENABLE_ASCON is defined the expected wire format is:
 *   [ciphertext || ascon_tag(16)] [extraNonce(4)]
 * so we extract the final 4 bytes as extraNonce and call ascon_decrypt on
 * the rest.
 *
 * @param fromNode The MeshPacket `from` field.
 * @param remotePublic The remote node's Curve25519 public key.
 * @param packetNum The MeshPacket `id` field.
 * @param numBytes Number of bytes of ciphertext in the bytes buffer.
 * @param bytes Buffer containing ciphertext input.
 * @param bytesOut Output buffer to be populated with decrypted plaintext.
 */
bool CryptoEngine::decryptCurve25519(uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic, uint64_t packetNum,
                                     size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut)
{
    if (remotePublic.size == 0) {
        LOG_DEBUG("Node or its public key not found in database");
        return false;
    }

#ifdef ENABLE_ASCON
    // Need at least tag + extraNonce
    if (numBytes < (ASCON_TAGLEN + sizeof(uint32_t))) {
        LOG_WARN("ASCON PKI packet too small (%zu)", numBytes);
        return false;
    }
    // Extract extraNonce (last 4 bytes)
    uint32_t extraNonce = 0;
    memcpy(&extraNonce, bytes + numBytes - sizeof(uint32_t), sizeof(uint32_t));
    // ciphertext+tag length
    size_t ctlen = numBytes - sizeof(uint32_t);

    // Derive shared key and ASCON key
    if (!crypto->setDHPublicKey(remotePublic.bytes)) {
        return false;
    }
    crypto->hash(shared_key, 32);
    uint8_t ascon_key[ASCON_KEYLEN];
    ascon_key_from_shared_truncate(shared_key, ascon_key);

    // Rebuild nonce
    initNonce(fromNode, packetNum, extraNonce);

    // Decrypt in-place: ascon_decrypt reads ct (ctlen) and writes plaintext into bytesOut
    size_t ptlen = 0;
    int r = ascon_decrypt(ascon_key, nonce, nullptr, 0, bytes, ctlen, bytesOut, &ptlen);
    if (r != 0) {
        LOG_WARN("ASCON decrypt attempted but failed (code %d)", r);
        return false;
    }
    // success
    return true;
#else
    // Legacy AES-CCM path
    if (numBytes < MESHTASTIC_PKC_OVERHEAD) {
        LOG_WARN("Legacy PKI packet too small (%zu)", numBytes);
        return false;
    }
    const uint8_t *auth = bytes + numBytes - MESHTASTIC_PKC_OVERHEAD;
    uint32_t extraNonce = 0;
    memcpy(&extraNonce, auth + 8, sizeof(uint32_t));
    size_t ciphertext_len = numBytes - MESHTASTIC_PKC_OVERHEAD;

    if (!crypto->setDHPublicKey(remotePublic.bytes)) {
        return false;
    }
    crypto->hash(shared_key, 32);
    initNonce(fromNode, packetNum, extraNonce);

    bool ok = aes_ccm_ad(shared_key, 32, nonce, 8, bytes, ciphertext_len, nullptr, 0, auth, bytesOut);
    if (!ok) {
        LOG_WARN("PKC decrypt attempted but failed!");
        return false;
    }
    return true;
#endif
}


void CryptoEngine::setDHPrivateKey(uint8_t *_private_key)
{
    memcpy(private_key, _private_key, 32);
}

/**
 * Hash arbitrary data using SHA256.
 *
 * @param bytes
 * @param numBytes
 */
void CryptoEngine::hash(uint8_t *bytes, size_t numBytes)
{
    SHA256 hash;
    size_t posn;
    uint8_t size = numBytes;
    uint8_t inc = 16;
    hash.reset();
    for (posn = 0; posn < size; posn += inc) {
        size_t len = size - posn;
        if (len > inc)
            len = inc;
        hash.update(bytes + posn, len);
    }
    hash.finalize(bytes, 32);
}

void CryptoEngine::aesSetKey(const uint8_t *key_bytes, size_t key_len)
{
    delete aes;
    aes = nullptr;
    if (key_len != 0) {
        aes = new AESSmall256();
        aes->setKey(key_bytes, key_len);
    }
}

void CryptoEngine::aesEncrypt(uint8_t *in, uint8_t *out)
{
    aes->encryptBlock(out, in);
}

bool CryptoEngine::setDHPublicKey(uint8_t *pubKey)
{
    uint8_t local_priv[32];
    memcpy(shared_key, pubKey, 32);
    memcpy(local_priv, private_key, 32);
    // Calculate the shared secret with the specified node's public key and our private key
    // This includes an internal weak key check, which among other things looks for an all 0 public key and shared key.
    if (!Curve25519::dh2(shared_key, local_priv)) {
        LOG_WARN("Curve25519DH step 2 failed!");
        return false;
    }
    return true;
}

#endif
concurrency::Lock *cryptLock;

void CryptoEngine::setKey(const CryptoKey &k)
{
    LOG_DEBUG("Use AES%d key!", k.length * 8);
    key = k;
}

/**
 * Encrypt a packet
 *
 * @param bytes is updated in place
 */
void CryptoEngine::encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes)
{
    if (key.length > 0) {
        initNonce(fromNode, packetId);
        if (numBytes <= MAX_BLOCKSIZE) {
            encryptAESCtr(key, nonce, numBytes, bytes);
        } else {
            LOG_ERROR("Packet too large for crypto engine: %d. noop encryption!", numBytes);
        }
    }
}

void CryptoEngine::decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes)
{
    // For CTR, the implementation is the same
    encryptPacket(fromNode, packetId, numBytes, bytes);
}

// Generic implementation of AES-CTR encryption.
void CryptoEngine::encryptAESCtr(CryptoKey _key, uint8_t *_nonce, size_t numBytes, uint8_t *bytes)
{
    delete ctr;
    ctr = nullptr;
    if (_key.length == 16)
        ctr = new CTR<AES128>();
    else
        ctr = new CTR<AES256>();
    ctr->setKey(_key.bytes, _key.length);
    static uint8_t scratch[MAX_BLOCKSIZE];
    memcpy(scratch, bytes, numBytes);
    memset(scratch + numBytes, 0,
           sizeof(scratch) - numBytes); // Fill rest of buffer with zero (in case cypher looks at it)

    ctr->setIV(_nonce, 16);
    ctr->setCounterSize(4);
    ctr->encrypt(bytes, scratch, numBytes);
}

/**
 * Init our 128 bit nonce for a new packet
 */
void CryptoEngine::initNonce(uint32_t fromNode, uint64_t packetId, uint32_t extraNonce)
{
    memset(nonce, 0, sizeof(nonce));

    // use memcpy to avoid breaking strict-aliasing
    memcpy(nonce, &packetId, sizeof(uint64_t));
    memcpy(nonce + sizeof(uint64_t), &fromNode, sizeof(uint32_t));
    if (extraNonce)
        memcpy(nonce + sizeof(uint32_t), &extraNonce, sizeof(uint32_t));
}
#ifndef HAS_CUSTOM_CRYPTO_ENGINE
CryptoEngine *crypto = new CryptoEngine;
#endif
