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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_LIBOQS
#error "This source should not be compiled without HAVE_LIBOQS defined"
#endif

#include <string.h>
#include <assert.h>

#include <oqs/oqs.h>
#include <nettle/sha2.h>
#include <nettle/curve25519.h>

#include <core/LogWriter.h>

#include <rdr/AESInStream.h>
#include <rdr/AESOutStream.h>
#include <rdr/RandomStream.h>

#include <rfb/SSecurityPQKEM.h>
#include <rfb/SConnection.h>
#include <rfb/Exception.h>
#include <rfb/SSecurityVncAuth.h>

#if !defined(WIN32) && !defined(__APPLE__)
#include <rfb/UnixPasswordValidator.h>
#endif
#ifdef WIN32
#include <rfb/WinPasswdValidator.h>
#endif

enum {
  SendPublicKeys,
  ReadEncapsulation,
  ReadHash,
  ReadCredentials,
};

using namespace rfb;

core::BoolParameter SSecurityPQKEM::requireUsername
("PQKEMRequireUsername",
 "Require username for the PQKEM security types",
 false);

static core::LogWriter vlog("SSecurityPQKEM");

SSecurityPQKEM::SSecurityPQKEM(SConnection* sc_, uint32_t _secType,
                               bool _isAllEncrypted)
  : SSecurity(sc_), state(SendPublicKeys),
    isAllEncrypted(_isAllEncrypted), secType(_secType),
    kemPubKey(nullptr), kemSecretKey(nullptr), kemSharedSecret(nullptr),
    kemPubKeyLen(0), kemSecretKeyLen(0), kemSharedSecretLen(0),
    accessRights(AccessDefault),
    rais(nullptr), raos(nullptr), rawis(nullptr), rawos(nullptr)
{
  memset(serverX25519Private, 0, sizeof(serverX25519Private));
  memset(serverX25519Public, 0, sizeof(serverX25519Public));
  memset(clientX25519Public, 0, sizeof(clientX25519Public));
  memset(ecdhSharedSecret, 0, sizeof(ecdhSharedSecret));
  memset(sessionKey, 0, sizeof(sessionKey));
  memset(username, 0, sizeof(username));
  memset(password, 0, sizeof(password));
}

SSecurityPQKEM::~SSecurityPQKEM()
{
  cleanup();
}

void SSecurityPQKEM::cleanup()
{
  if (raos) {
    try {
      if (raos->hasBufferedData()) {
        raos->cork(false);
        raos->flush();
        if (raos->hasBufferedData())
          vlog.error("Failed to flush remaining socket data on close");
      }
    } catch (std::exception& e) {
      vlog.error("Failed to flush remaining socket data on close: %s",
                 e.what());
    }
  }

  if (kemPubKey) {
    OQS_MEM_cleanse(kemPubKey, kemPubKeyLen);
    delete[] kemPubKey;
    kemPubKey = nullptr;
  }
  if (kemSecretKey) {
    OQS_MEM_cleanse(kemSecretKey, kemSecretKeyLen);
    delete[] kemSecretKey;
    kemSecretKey = nullptr;
  }
  if (kemSharedSecret) {
    OQS_MEM_cleanse(kemSharedSecret, kemSharedSecretLen);
    delete[] kemSharedSecret;
    kemSharedSecret = nullptr;
  }

  if (isAllEncrypted && rawis && rawos)
    sc->setStreams(rawis, rawos);
  if (rais)
    delete rais;
  if (raos)
    delete raos;
}

bool SSecurityPQKEM::processMsg()
{
  switch (state) {
    case SendPublicKeys:
      generateAndSendKeys();
      state = ReadEncapsulation;
      /* fall through */
    case ReadEncapsulation:
      if (!readEncapsulation())
        return false;
      setCipher();
      writeHash();
      state = ReadHash;
      /* fall through */
    case ReadHash:
      if (!readHash())
        return false;
      clearSecrets();
      writeSubtype();
      state = ReadCredentials;
      /* fall through */
    case ReadCredentials:
      if (!readCredentials())
        return false;
      if (requireUsername)
        verifyUserPass();
      else
        verifyPass();
      return true;
  }

  throw std::logic_error("Invalid state");

  return false;
}

void SSecurityPQKEM::generateAndSendKeys()
{
  rdr::OutStream* os = sc->getOutStream();
  rdr::RandomStream rs;

  // --- ML-KEM-768 keypair ---
  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem)
    throw std::runtime_error("Failed to initialise ML-KEM-768");

  kemPubKeyLen = kem->length_public_key;
  kemSecretKeyLen = kem->length_secret_key;
  kemSharedSecretLen = kem->length_shared_secret;

  kemPubKey = new uint8_t[kemPubKeyLen];
  kemSecretKey = new uint8_t[kemSecretKeyLen];
  kemSharedSecret = new uint8_t[kemSharedSecretLen];

  if (OQS_KEM_keypair(kem, kemPubKey, kemSecretKey) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    throw std::runtime_error("ML-KEM-768 keypair generation failed");
  }
  OQS_KEM_free(kem);

  // --- X25519 keypair ---
  if (!rs.hasData(32))
    throw std::runtime_error("Failed to generate X25519 private key");
  rs.readBytes(serverX25519Private, 32);

  // Public key = private * basepoint
  static const uint8_t basepoint[32] = { 9 };
  curve25519_mul(serverX25519Public, serverX25519Private, basepoint);

  // --- Send: U16(kemPubKeyLen) || kemPubKey || x25519Public(32) ---
  os->writeU16((uint16_t)kemPubKeyLen);
  os->writeBytes(kemPubKey, kemPubKeyLen);
  os->writeBytes(serverX25519Public, 32);
  os->flush();
}

bool SSecurityPQKEM::readEncapsulation()
{
  rdr::InStream* is = sc->getInStream();

  // Need at least 2 bytes for ciphertext length
  if (!is->hasData(2))
    return false;
  is->setRestorePoint();

  size_t ctLen = is->readU16();
  // Expect ciphertext + 32 bytes of client X25519 public key
  if (!is->hasDataOrRestore(ctLen + 32))
    return false;
  is->clearRestorePoint();

  // Read KEM ciphertext
  uint8_t* ciphertext = new uint8_t[ctLen];
  is->readBytes(ciphertext, ctLen);

  // Read client X25519 public key
  is->readBytes(clientX25519Public, 32);

  // --- ML-KEM decapsulation ---
  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    delete[] ciphertext;
    throw std::runtime_error("Failed to initialise ML-KEM-768");
  }

  if (ctLen != kem->length_ciphertext) {
    OQS_KEM_free(kem);
    delete[] ciphertext;
    throw protocol_error("KEM ciphertext length mismatch");
  }

  if (OQS_KEM_decaps(kem, kemSharedSecret, ciphertext, kemSecretKey)
      != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    delete[] ciphertext;
    throw protocol_error("ML-KEM-768 decapsulation failed");
  }
  OQS_KEM_free(kem);

  // --- X25519 ECDH ---
  curve25519_mul(ecdhSharedSecret, serverX25519Private, clientX25519Public);

  // --- Precompute transcript hashes while ciphertext is still available ---
  // sessionKey[0..31]  = server hash (what we send to the client)
  //   SHA-256(serverKEMPubKey || serverX25519Public || kemCiphertext || clientX25519Public)
  // sessionKey[32..63] = expected client hash (what we expect to receive)
  //   SHA-256(kemCiphertext || clientX25519Public || serverKEMPubKey || serverX25519Public)
  {
    struct sha256_ctx ctx;

    // Server hash
    sha256_init(&ctx);
    sha256_update(&ctx, kemPubKeyLen, kemPubKey);
    sha256_update(&ctx, 32, serverX25519Public);
    sha256_update(&ctx, ctLen, ciphertext);
    sha256_update(&ctx, 32, clientX25519Public);
    sha256_digest(&ctx, 32, sessionKey);

    // Expected client hash
    sha256_init(&ctx);
    sha256_update(&ctx, ctLen, ciphertext);
    sha256_update(&ctx, 32, clientX25519Public);
    sha256_update(&ctx, kemPubKeyLen, kemPubKey);
    sha256_update(&ctx, 32, serverX25519Public);
    sha256_digest(&ctx, 32, sessionKey + 32);
  }

  delete[] ciphertext;

  return true;
}

void SSecurityPQKEM::setCipher()
{
  rawis = sc->getInStream();
  rawos = sc->getOutStream();

  // readKey = SHA-256(kemSharedSecret || ecdhSharedSecret || "QuantaVNC-PQKEM-C2S")
  // Server reads what client sends, so readKey uses the C2S label.
  uint8_t readKey[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, kemSharedSecretLen, kemSharedSecret);
    sha256_update(&ctx, 32, ecdhSharedSecret);
    const char* label = "QuantaVNC-PQKEM-C2S";
    sha256_update(&ctx, strlen(label), (const uint8_t*)label);
    sha256_digest(&ctx, 32, readKey);
  }

  // writeKey = SHA-256(kemSharedSecret || ecdhSharedSecret || "QuantaVNC-PQKEM-S2C")
  // Server writes to client, so writeKey uses the S2C label.
  uint8_t writeKey[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, kemSharedSecretLen, kemSharedSecret);
    sha256_update(&ctx, 32, ecdhSharedSecret);
    const char* label = "QuantaVNC-PQKEM-S2C";
    sha256_update(&ctx, strlen(label), (const uint8_t*)label);
    sha256_digest(&ctx, 32, writeKey);
  }

  rais = new rdr::AESInStream(rawis, readKey, 256);
  raos = new rdr::AESOutStream(rawos, writeKey, 256);

  memset(readKey, 0, sizeof(readKey));
  memset(writeKey, 0, sizeof(writeKey));

  if (isAllEncrypted)
    sc->setStreams(rais, raos);
}

void SSecurityPQKEM::writeHash()
{
  // Send the precomputed server hash from sessionKey[0..31]
  // Hash = SHA-256(serverKEMPubKey || serverX25519Public ||
  //               kemCiphertext || clientX25519Public)
  raos->writeBytes(sessionKey, 32);
  raos->flush();
}

bool SSecurityPQKEM::readHash()
{
  // Read and verify client hash against sessionKey[32..63]
  // Expected = SHA-256(kemCiphertext || clientX25519Public ||
  //                    serverKEMPubKey || serverX25519Public)
  if (!rais->hasData(32))
    return false;

  uint8_t hash[32];
  rais->readBytes(hash, 32);

  if (memcmp(hash, sessionKey + 32, 32) != 0)
    throw protocol_error("Hash doesn't match");

  return true;
}

void SSecurityPQKEM::clearSecrets()
{
  if (kemPubKey) {
    OQS_MEM_cleanse(kemPubKey, kemPubKeyLen);
    delete[] kemPubKey;
    kemPubKey = nullptr;
  }
  if (kemSecretKey) {
    OQS_MEM_cleanse(kemSecretKey, kemSecretKeyLen);
    delete[] kemSecretKey;
    kemSecretKey = nullptr;
  }
  if (kemSharedSecret) {
    OQS_MEM_cleanse(kemSharedSecret, kemSharedSecretLen);
    delete[] kemSharedSecret;
    kemSharedSecret = nullptr;
  }

  OQS_MEM_cleanse(serverX25519Private, sizeof(serverX25519Private));
  OQS_MEM_cleanse(ecdhSharedSecret, sizeof(ecdhSharedSecret));
  memset(sessionKey, 0, sizeof(sessionKey));
}

void SSecurityPQKEM::writeSubtype()
{
  if (requireUsername)
    raos->writeU8(secTypeRA2UserPass);
  else
    raos->writeU8(secTypeRA2Pass);
  raos->flush();
}

bool SSecurityPQKEM::readCredentials()
{
  if (!rais->hasData(1))
    return false;
  rais->setRestorePoint();
  uint8_t lenUsername = rais->readU8();
  if (!rais->hasDataOrRestore(lenUsername + 1))
    return false;
  rais->readBytes((uint8_t*)username, lenUsername);
  username[lenUsername] = 0;
  uint8_t lenPassword = rais->readU8();
  if (!rais->hasDataOrRestore(lenPassword))
    return false;
  rais->readBytes((uint8_t*)password, lenPassword);
  password[lenPassword] = 0;
  rais->clearRestorePoint();
  return true;
}

void SSecurityPQKEM::verifyUserPass()
{
#ifndef __APPLE__
#ifdef WIN32
  WinPasswdValidator* valid = new WinPasswdValidator();
#elif !defined(__APPLE__)
  UnixPasswordValidator* valid = new UnixPasswordValidator();
#endif
  std::string msg = "Authentication failed";
  if (!valid->validate(sc, username, password, msg)) {
    delete valid;
    throw auth_error(msg);
  }
  delete valid;
#else
  throw std::logic_error("No password validator configured");
#endif
}

void SSecurityPQKEM::verifyPass()
{
  VncAuthPasswdGetter* pg = &SSecurityVncAuth::vncAuthPasswd;
  std::string passwd, passwdReadOnly;
  pg->getVncAuthPasswd(&passwd, &passwdReadOnly);

  if (passwd.empty())
    throw std::runtime_error("No password configured");

  if (password == passwd) {
    accessRights = AccessDefault;
    return;
  }

  if (!passwdReadOnly.empty() && password == passwdReadOnly) {
    accessRights = AccessView;
    return;
  }

  throw auth_error("Authentication failed");
}

const char* SSecurityPQKEM::getUserName() const
{
  return username;
}
