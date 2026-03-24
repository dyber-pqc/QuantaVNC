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

#ifndef __C_SECURITY_PQKEM_H__
#define __C_SECURITY_PQKEM_H__

#ifndef HAVE_LIBOQS
#error "This header should not be compiled without HAVE_LIBOQS defined"
#endif

#include <oqs/oqs.h>

#include <rfb/CSecurity.h>
#include <rfb/Security.h>

namespace rdr {
  class InStream;
  class OutStream;
  class AESInStream;
  class AESOutStream;
}

namespace rfb {

  class CSecurityPQKEM : public CSecurity {
  public:
    CSecurityPQKEM(CConnection* cc, uint32_t secType,
                   bool isAllEncrypted);
    virtual ~CSecurityPQKEM();
    bool processMsg() override;
    int getType() const override { return secType; }
    bool isSecure() const override { return true; }

  private:
    void cleanup();
    bool readServerPublicKeys();
    void verifyServer();
    void writeEncapsulation();
    void setCipher();
    void writeHash();
    bool readHash();
    void clearSecrets();
    bool readSubtype();
    void writeCredentials();

    int state;
    bool isAllEncrypted;
    uint32_t secType;
    uint8_t subtype;

    // ML-KEM
    uint8_t* serverKEMPubKey;
    uint8_t* kemCiphertext;
    uint8_t* kemSharedSecret;
    size_t kemPubKeyLen;
    size_t kemCiphertextLen;
    size_t kemSharedSecretLen;

    // X25519 hybrid
    uint8_t clientX25519Private[32];
    uint8_t clientX25519Public[32];
    uint8_t serverX25519Public[32];
    uint8_t ecdhSharedSecret[32];

    // Combined key material for hashing
    uint8_t sessionKey[64]; // 32 bytes for read key, 32 for write key

    rdr::AESInStream* rais;
    rdr::AESOutStream* raos;
    rdr::InStream* rawis;
    rdr::OutStream* rawos;
  };

}

#endif
