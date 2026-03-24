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

#ifndef __S_SECURITY_PQKEM_H__
#define __S_SECURITY_PQKEM_H__

#ifndef HAVE_LIBOQS
#error "This header should not be included without HAVE_LIBOQS defined"
#endif

#include <oqs/oqs.h>

#include <rfb/SSecurity.h>
#include <rfb/PQCAlgorithm.h>

namespace core {
  class BoolParameter;
}

namespace rdr {
  class InStream;
  class OutStream;
  class AESInStream;
  class AESOutStream;
}

namespace rfb {

  class SSecurityPQKEM : public SSecurity {
  public:
    SSecurityPQKEM(SConnection* sc, uint32_t secType,
                   bool isAllEncrypted);
    virtual ~SSecurityPQKEM();
    bool processMsg() override;
    const char* getUserName() const override;
    int getType() const override { return secType; }
    AccessRights getAccessRights() const override { return accessRights; }

    static core::BoolParameter requireUsername;

  private:
    void cleanup();
    void generateAndSendKeys();
    bool readEncapsulation();
    void setCipher();
    void writeHash();
    bool readHash();
    void clearSecrets();
    void writeSubtype();
    bool readCredentials();
    void verifyUserPass();
    void verifyPass();

    int state;
    bool isAllEncrypted;
    uint32_t secType;
    uint8_t selectedAlg;

    // ML-KEM
    uint8_t* kemPubKey;
    uint8_t* kemSecretKey;
    uint8_t* kemSharedSecret;
    size_t kemPubKeyLen;
    size_t kemSecretKeyLen;
    size_t kemSharedSecretLen;

    // X25519
    uint8_t serverX25519Private[32];
    uint8_t serverX25519Public[32];
    uint8_t clientX25519Public[32];
    uint8_t ecdhSharedSecret[32];

    // Derived session keys
    uint8_t sessionKey[64];

    char username[256];
    char password[256];
    AccessRights accessRights;

    rdr::AESInStream* rais;
    rdr::AESOutStream* raos;
    rdr::InStream* rawis;
    rdr::OutStream* rawos;
  };

}

#endif
