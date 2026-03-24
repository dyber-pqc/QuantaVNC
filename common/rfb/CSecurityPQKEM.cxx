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
#error "This header should not be compiled without HAVE_LIBOQS defined"
#endif

#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <assert.h>
#include <string.h>

#include <oqs/oqs.h>
#include <nettle/sha2.h>
#include <nettle/curve25519.h>

#include <rfb/PQCAlgorithm.h>
#include <rfb/CSecurityPQKEM.h>
#include <rfb/CConnection.h>
#include <rfb/Exception.h>

#include <rdr/AESInStream.h>
#include <rdr/AESOutStream.h>
#include <rdr/RandomStream.h>

#include <core/LogWriter.h>
#include <core/string.h>

enum {
  ReadServerPublicKeys,
  ReadHash,
  ReadSubtype,
};

using namespace rfb;

static core::LogWriter vlog("CSecurityPQKEM");

CSecurityPQKEM::CSecurityPQKEM(CConnection* cc_, uint32_t _secType,
                               bool _isAllEncrypted)
  : CSecurity(cc_), state(ReadServerPublicKeys),
    isAllEncrypted(_isAllEncrypted), secType(_secType), subtype(0), selectedAlg(0),
    serverKEMPubKey(nullptr), kemCiphertext(nullptr),
    kemSharedSecret(nullptr),
    kemPubKeyLen(0), kemCiphertextLen(0), kemSharedSecretLen(0),
    rais(nullptr), raos(nullptr), rawis(nullptr), rawos(nullptr)
{
  memset(clientX25519Private, 0, sizeof(clientX25519Private));
  memset(clientX25519Public, 0, sizeof(clientX25519Public));
  memset(serverX25519Public, 0, sizeof(serverX25519Public));
  memset(ecdhSharedSecret, 0, sizeof(ecdhSharedSecret));
  memset(sessionKey, 0, sizeof(sessionKey));
}

CSecurityPQKEM::~CSecurityPQKEM()
{
  cleanup();
}

void CSecurityPQKEM::cleanup()
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

  if (serverKEMPubKey)
    delete[] serverKEMPubKey;
  if (kemCiphertext)
    delete[] kemCiphertext;
  if (kemSharedSecret)
    delete[] kemSharedSecret;

  if (isAllEncrypted && rawis && rawos)
    cc->setStreams(rawis, rawos);
  if (rais)
    delete rais;
  if (raos)
    delete raos;
}

bool CSecurityPQKEM::processMsg()
{
  switch (state) {
    case ReadServerPublicKeys:
      if (!readServerPublicKeys())
        return false;
      verifyServer();
      writeEncapsulation();
      setCipher();
      writeHash();
      state = ReadHash;
      /* fall through */
    case ReadHash:
      if (!readHash())
        return false;
      clearSecrets();
      state = ReadSubtype;
      /* fall through */
    case ReadSubtype:
      if (!readSubtype())
        return false;
      writeCredentials();
      return true;
  }

  throw std::logic_error("Invalid state");

  return false;
}

bool CSecurityPQKEM::readServerPublicKeys()
{
  rdr::InStream* is = cc->getInStream();

  // Need at least 1 byte for algorithm count
  if (!is->hasData(1))
    return false;
  is->setRestorePoint();

  // --- Read algorithm negotiation ---
  // Wire format: U8(numAlgorithms) || U8(algId)... || U8(selectedAlg)
  uint8_t numAlgs = is->readU8();
  if (numAlgs == 0 || numAlgs > 16)
    throw protocol_error("Invalid PQC algorithm count");

  // Need algorithm list + selected byte + 2 bytes for key length
  if (!is->hasDataOrRestore(numAlgs + 1 + 2))
    return false;

  std::vector<uint8_t> serverAlgs(numAlgs);
  for (uint8_t i = 0; i < numAlgs; i++)
    serverAlgs[i] = is->readU8();

  selectedAlg = is->readU8();

  // Verify client supports the selected algorithm
  OQS_KEM* testKem = OQS_KEM_new(pqkemAlgOQSName(selectedAlg));
  if (!testKem)
    throw protocol_error("Server selected unsupported PQC algorithm");
  OQS_KEM_free(testKem);

  vlog.info("PQC algorithm negotiation: server selected %s "
            "(%d algorithm(s) offered)",
            pqkemAlgDisplayName(selectedAlg), (int)numAlgs);

  // --- Read public keys ---
  uint16_t pubKeyLen = is->readU16();
  kemPubKeyLen = pubKeyLen;

  if (kemPubKeyLen == 0 || kemPubKeyLen > 4096)
    throw protocol_error("Invalid KEM public key length");

  // Need kemPubKeyLen + 32 bytes (X25519 public key)
  if (!is->hasDataOrRestore(kemPubKeyLen + 32))
    return false;
  is->clearRestorePoint();

  serverKEMPubKey = new uint8_t[kemPubKeyLen];
  is->readBytes(serverKEMPubKey, kemPubKeyLen);
  is->readBytes(serverX25519Public, 32);

  vlog.info("Received server KEM public key (%d bytes) and X25519 key",
            (int)kemPubKeyLen);

  return true;
}

void CSecurityPQKEM::verifyServer()
{
  // Compute SHA-256 fingerprint of the server's KEM public key
  uint8_t hash[32];
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, kemPubKeyLen, serverKEMPubKey);
  sha256_digest(&ctx, sizeof(hash), hash);

  // Display first 8 bytes as fingerprint
  uint8_t f[8];
  memcpy(f, hash, 8);

  const char *title = "Server key fingerprint";
  std::string text = core::format(
    "The server has provided the following identifying information:\n"
    "Fingerprint: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n"
    "Please verify that the information is correct and press \"Yes\". "
    "Otherwise press \"No\"",
    f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
  if (!cc->showMsgBox(MsgBoxFlags::M_YESNO, title, text.c_str()))
    throw auth_cancelled();
}

void CSecurityPQKEM::writeEncapsulation()
{
  rdr::OutStream* os = cc->getOutStream();

  // --- ML-KEM encapsulation using negotiated algorithm ---
  OQS_KEM* kem = OQS_KEM_new(pqkemAlgOQSName(selectedAlg));
  if (kem == nullptr)
    throw std::runtime_error("Failed to initialize KEM algorithm");

  kemCiphertextLen = kem->length_ciphertext;
  kemSharedSecretLen = kem->length_shared_secret;
  kemCiphertext = new uint8_t[kemCiphertextLen];
  kemSharedSecret = new uint8_t[kemSharedSecretLen];

  OQS_STATUS rc = OQS_KEM_encaps(kem, kemCiphertext, kemSharedSecret,
                                  serverKEMPubKey);
  OQS_KEM_free(kem);
  if (rc != OQS_SUCCESS) {
    throw std::runtime_error("ML-KEM encapsulation failed");
  }

  // --- X25519 key agreement ---
  // Generate client X25519 private key
  rdr::RandomStream rs;
  if (!rs.hasData(32))
    throw std::runtime_error("Failed to generate random for X25519");
  rs.readBytes(clientX25519Private, 32);

  // Clamp the private key per X25519 convention
  clientX25519Private[0] &= 248;
  clientX25519Private[31] &= 127;
  clientX25519Private[31] |= 64;

  // Compute client X25519 public key: clientPublic = privKey * basepoint
  static const uint8_t basepoint[32] = { 9 };
  curve25519_mul(clientX25519Public, clientX25519Private, basepoint);

  // Compute ECDH shared secret: ecdhSecret = privKey * serverPublic
  curve25519_mul(ecdhSharedSecret, clientX25519Private, serverX25519Public);

  // --- Send encapsulation to server ---
  os->writeU16(kemCiphertextLen);
  os->writeBytes(kemCiphertext, kemCiphertextLen);
  os->writeBytes(clientX25519Public, 32);
  os->flush();

  vlog.info("Sent KEM ciphertext (%d bytes) and X25519 public key",
            (int)kemCiphertextLen);
}

void CSecurityPQKEM::setCipher()
{
  rawis = cc->getInStream();
  rawos = cc->getOutStream();

  // Derive client->server key:
  //   SHA-256(kemSharedSecret || ecdhSharedSecret || U8(selectedAlg) || "QuantaVNC-PQKEM-C2S")
  // The algorithm ID is included to cryptographically bind the negotiated algorithm.
  uint8_t c2sKey[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, kemSharedSecretLen, kemSharedSecret);
    sha256_update(&ctx, 32, ecdhSharedSecret);
    sha256_update(&ctx, 1, &selectedAlg);
    const char* label = "QuantaVNC-PQKEM-C2S";
    sha256_update(&ctx, strlen(label), (const uint8_t*)label);
    sha256_digest(&ctx, 32, c2sKey);
  }

  // Derive server->client key:
  //   SHA-256(kemSharedSecret || ecdhSharedSecret || U8(selectedAlg) || "QuantaVNC-PQKEM-S2C")
  uint8_t s2cKey[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, kemSharedSecretLen, kemSharedSecret);
    sha256_update(&ctx, 32, ecdhSharedSecret);
    sha256_update(&ctx, 1, &selectedAlg);
    const char* label = "QuantaVNC-PQKEM-S2C";
    sha256_update(&ctx, strlen(label), (const uint8_t*)label);
    sha256_digest(&ctx, 32, s2cKey);
  }

  // Store session keys
  memcpy(sessionKey, s2cKey, 32);      // read key (server->client)
  memcpy(sessionKey + 32, c2sKey, 32); // write key (client->server)

  // Always AES-256-EAX
  rais = new rdr::AESInStream(rawis, s2cKey, 256);
  raos = new rdr::AESOutStream(rawos, c2sKey, 256);

  if (isAllEncrypted)
    cc->setStreams(rais, raos);
}

void CSecurityPQKEM::writeHash()
{
  // Hash over algorithm ID and all exchanged key material:
  //   SHA-256(U8(selectedAlg) || kemCiphertext || clientX25519Public ||
  //           serverKEMPubKey || serverX25519Public)
  // Algorithm ID is included to prevent downgrade attacks.
  uint8_t hash[32];
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, 1, &selectedAlg);
  sha256_update(&ctx, kemCiphertextLen, kemCiphertext);
  sha256_update(&ctx, 32, clientX25519Public);
  sha256_update(&ctx, kemPubKeyLen, serverKEMPubKey);
  sha256_update(&ctx, 32, serverX25519Public);
  sha256_digest(&ctx, 32, hash);

  raos->writeBytes(hash, 32);
  raos->flush();
}

bool CSecurityPQKEM::readHash()
{
  if (!rais->hasData(32))
    return false;

  uint8_t hash[32];
  rais->readBytes(hash, 32);

  // Server hash includes algorithm ID:
  //   SHA-256(U8(selectedAlg) || serverKEMPubKey || serverX25519Public ||
  //           kemCiphertext || clientX25519Public)
  uint8_t realHash[32];
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, 1, &selectedAlg);
  sha256_update(&ctx, kemPubKeyLen, serverKEMPubKey);
  sha256_update(&ctx, 32, serverX25519Public);
  sha256_update(&ctx, kemCiphertextLen, kemCiphertext);
  sha256_update(&ctx, 32, clientX25519Public);
  sha256_digest(&ctx, 32, realHash);

  if (memcmp(hash, realHash, 32) != 0)
    throw protocol_error("Hash doesn't match");

  return true;
}

void CSecurityPQKEM::clearSecrets()
{
  if (kemSharedSecret) {
    memset(kemSharedSecret, 0, kemSharedSecretLen);
    delete[] kemSharedSecret;
    kemSharedSecret = nullptr;
  }
  if (kemCiphertext) {
    delete[] kemCiphertext;
    kemCiphertext = nullptr;
  }
  if (serverKEMPubKey) {
    delete[] serverKEMPubKey;
    serverKEMPubKey = nullptr;
  }

  memset(clientX25519Private, 0, sizeof(clientX25519Private));
  memset(ecdhSharedSecret, 0, sizeof(ecdhSharedSecret));
  memset(sessionKey, 0, sizeof(sessionKey));
}

bool CSecurityPQKEM::readSubtype()
{
  if (!rais->hasData(1))
    return false;
  subtype = rais->readU8();
  if (subtype != secTypeRA2UserPass && subtype != secTypeRA2Pass)
    throw protocol_error("Unknown PQKEM subtype");
  return true;
}

void CSecurityPQKEM::writeCredentials()
{
  std::string username;
  std::string password;

  if (subtype == secTypeRA2UserPass)
    cc->getUserPasswd(isSecure(), &username, &password);
  else
    cc->getUserPasswd(isSecure(), nullptr, &password);

  if (subtype == secTypeRA2UserPass) {
    if (username.size() > 255)
      throw std::out_of_range("Username is too long");
    raos->writeU8(username.size());
    raos->writeBytes((const uint8_t*)username.data(), username.size());
  } else {
    raos->writeU8(0);
  }

  if (password.size() > 255)
    throw std::out_of_range("Password is too long");
  raos->writeU8(password.size());
  raos->writeBytes((const uint8_t*)password.data(), password.size());
  raos->flush();
}
