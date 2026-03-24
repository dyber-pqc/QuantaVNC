/*
 * QuantaVNC - Post-Quantum Cryptography VNC Platform
 * Copyright (C) 2026 Dyber, Inc.
 *
 * Based on TigerVNC -- Copyright (C) 2009-2026 TigerVNC Team and contributors
 * See LICENCE.TXT for full license terms (GNU General Public License v2)
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __PQC_KEYSTORE_H__
#define __PQC_KEYSTORE_H__

#ifndef HAVE_LIBOQS
#error "This header should not be included without HAVE_LIBOQS defined"
#endif

#include <stdint.h>
#include <string>

namespace rfb {

  // Manages persistent ML-DSA signing keys for server authentication.
  // Keys are stored on disk and loaded at server startup.
  class PQCKeyStore {
  public:
    PQCKeyStore();
    ~PQCKeyStore();

    // Load an existing keypair from file, or generate and save a new one.
    // Returns true on success.
    bool loadOrGenerate(const char* keyPath, uint8_t dsaAlg);

    // Accessors
    const uint8_t* getPublicKey() const { return pubKey; }
    size_t getPublicKeyLen() const { return pubKeyLen; }
    const uint8_t* getSecretKey() const { return secKey; }
    size_t getSecretKeyLen() const { return secKeyLen; }
    uint8_t getAlgorithm() const { return algorithm; }
    bool isLoaded() const { return loaded; }

    // Generate a keypair in memory only (no file I/O). For testing.
    bool generateForTest(uint8_t dsaAlg);

    // Compute SHA-256 fingerprint of the ML-DSA public key.
    // Returns hex string like "ab:cd:ef:..."
    std::string computeFingerprint() const;

    // Sign a message. Caller must free *sig with OQS_MEM_cleanse + delete[].
    bool sign(const uint8_t* msg, size_t msgLen,
              uint8_t** sig, size_t* sigLen) const;

    // Verify a signature against a public key (static, no instance needed).
    static bool verify(uint8_t dsaAlg,
                       const uint8_t* pubKey, size_t pubKeyLen,
                       const uint8_t* msg, size_t msgLen,
                       const uint8_t* sig, size_t sigLen);

  private:
    bool loadFromFile(const char* path);
    bool saveToFile(const char* path);
    bool generateKeypair(uint8_t dsaAlg);
    void cleanup();

    uint8_t* pubKey;
    uint8_t* secKey;
    size_t pubKeyLen;
    size_t secKeyLen;
    uint8_t algorithm;
    bool loaded;

    // File format magic: "PQSK" (PQ Signing Key)
    static const uint32_t MAGIC = 0x504B5351;  // "PQSK" in little-endian
    static const uint8_t VERSION = 1;
  };

}

#endif
