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
#include <stdio.h>
#include <errno.h>

#ifndef WIN32
#include <sys/stat.h>
#endif

#include <oqs/oqs.h>
#include <nettle/sha2.h>

#include <core/LogWriter.h>

#include <rfb/PQCKeyStore.h>
#include <rfb/PQCSignature.h>

using namespace rfb;

static core::LogWriter vlog("PQCKeyStore");

PQCKeyStore::PQCKeyStore()
  : pubKey(nullptr), secKey(nullptr),
    pubKeyLen(0), secKeyLen(0),
    algorithm(0), loaded(false)
{
}

PQCKeyStore::~PQCKeyStore()
{
  cleanup();
}

void PQCKeyStore::cleanup()
{
  if (secKey) {
    OQS_MEM_cleanse(secKey, secKeyLen);
    delete[] secKey;
    secKey = nullptr;
  }
  if (pubKey) {
    delete[] pubKey;
    pubKey = nullptr;
  }
  pubKeyLen = 0;
  secKeyLen = 0;
  loaded = false;
}

bool PQCKeyStore::loadOrGenerate(const char* keyPath, uint8_t dsaAlg)
{
  cleanup();

  // Try to load existing key
  if (loadFromFile(keyPath)) {
    if (algorithm == dsaAlg) {
      vlog.info("Loaded ML-DSA signing key from %s (algorithm: %s)",
                keyPath, pqdsaAlgDisplayName(algorithm));
      return true;
    }
    vlog.info("Existing key uses different algorithm, regenerating");
    cleanup();
  }

  // Generate new keypair
  if (!generateKeypair(dsaAlg))
    return false;

  // Save to file
  if (!saveToFile(keyPath)) {
    vlog.error("Failed to save signing key to %s", keyPath);
    // Key is still usable in memory for this session
  } else {
    vlog.info("Generated and saved new ML-DSA signing key to %s "
              "(algorithm: %s)", keyPath, pqdsaAlgDisplayName(dsaAlg));
  }

  return true;
}

bool PQCKeyStore::generateForTest(uint8_t dsaAlg)
{
  cleanup();
  return generateKeypair(dsaAlg);
}

bool PQCKeyStore::generateKeypair(uint8_t dsaAlg)
{
  const char* oqsName = pqdsaAlgOQSName(dsaAlg);
  if (!oqsName)
    return false;

  OQS_SIG* sig = OQS_SIG_new(oqsName);
  if (!sig)
    return false;

  pubKeyLen = sig->length_public_key;
  secKeyLen = sig->length_secret_key;
  pubKey = new uint8_t[pubKeyLen];
  secKey = new uint8_t[secKeyLen];

  if (OQS_SIG_keypair(sig, pubKey, secKey) != OQS_SUCCESS) {
    OQS_SIG_free(sig);
    cleanup();
    return false;
  }

  OQS_SIG_free(sig);
  algorithm = dsaAlg;
  loaded = true;
  return true;
}

bool PQCKeyStore::loadFromFile(const char* path)
{
  FILE* f = fopen(path, "rb");
  if (!f)
    return false;

  // Read and verify header
  uint32_t magic;
  uint8_t version, algId;
  uint32_t pkLen, skLen;

  if (fread(&magic, 4, 1, f) != 1 || magic != MAGIC) {
    fclose(f);
    return false;
  }
  if (fread(&version, 1, 1, f) != 1 || version != VERSION) {
    fclose(f);
    return false;
  }
  if (fread(&algId, 1, 1, f) != 1) {
    fclose(f);
    return false;
  }
  if (fread(&pkLen, 4, 1, f) != 1 || pkLen > 65536) {
    fclose(f);
    return false;
  }

  pubKey = new uint8_t[pkLen];
  pubKeyLen = pkLen;
  if (fread(pubKey, 1, pkLen, f) != pkLen) {
    fclose(f);
    cleanup();
    return false;
  }

  if (fread(&skLen, 4, 1, f) != 1 || skLen > 65536) {
    fclose(f);
    cleanup();
    return false;
  }

  secKey = new uint8_t[skLen];
  secKeyLen = skLen;
  if (fread(secKey, 1, skLen, f) != skLen) {
    fclose(f);
    cleanup();
    return false;
  }

  fclose(f);
  algorithm = algId;
  loaded = true;
  return true;
}

bool PQCKeyStore::saveToFile(const char* path)
{
  FILE* f = fopen(path, "wb");
  if (!f)
    return false;

#ifndef WIN32
  // Set restrictive permissions (owner-only read/write)
  chmod(path, 0600);
#endif

  uint32_t magic = MAGIC;
  uint8_t version = VERSION;
  uint32_t pkLen = (uint32_t)pubKeyLen;
  uint32_t skLen = (uint32_t)secKeyLen;

  bool ok = true;
  ok = ok && fwrite(&magic, 4, 1, f) == 1;
  ok = ok && fwrite(&version, 1, 1, f) == 1;
  ok = ok && fwrite(&algorithm, 1, 1, f) == 1;
  ok = ok && fwrite(&pkLen, 4, 1, f) == 1;
  ok = ok && fwrite(pubKey, 1, pubKeyLen, f) == pubKeyLen;
  ok = ok && fwrite(&skLen, 4, 1, f) == 1;
  ok = ok && fwrite(secKey, 1, secKeyLen, f) == secKeyLen;

  fclose(f);
  return ok;
}

std::string PQCKeyStore::computeFingerprint() const
{
  if (!loaded || !pubKey)
    return "";

  uint8_t hash[32];
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, pubKeyLen, pubKey);
  sha256_digest(&ctx, 32, hash);

  char hex[97]; // 32 * 3 - 1 + null
  for (int i = 0; i < 32; i++) {
    snprintf(hex + i * 3, 4, "%02x%s", hash[i], i < 31 ? ":" : "");
  }
  return std::string(hex);
}

bool PQCKeyStore::sign(const uint8_t* msg, size_t msgLen,
                       uint8_t** outSig, size_t* outSigLen) const
{
  if (!loaded || !secKey)
    return false;

  const char* oqsName = pqdsaAlgOQSName(algorithm);
  if (!oqsName)
    return false;

  OQS_SIG* sig = OQS_SIG_new(oqsName);
  if (!sig)
    return false;

  *outSig = new uint8_t[sig->length_signature];
  *outSigLen = sig->length_signature;

  if (OQS_SIG_sign(sig, *outSig, outSigLen, msg, msgLen, secKey)
      != OQS_SUCCESS) {
    OQS_SIG_free(sig);
    delete[] *outSig;
    *outSig = nullptr;
    *outSigLen = 0;
    return false;
  }

  OQS_SIG_free(sig);
  return true;
}

bool PQCKeyStore::verify(uint8_t dsaAlg,
                         const uint8_t* pk, size_t pkLen,
                         const uint8_t* msg, size_t msgLen,
                         const uint8_t* signature, size_t sigLen)
{
  const char* oqsName = pqdsaAlgOQSName(dsaAlg);
  if (!oqsName)
    return false;

  OQS_SIG* sig = OQS_SIG_new(oqsName);
  if (!sig)
    return false;

  OQS_STATUS rc = OQS_SIG_verify(sig, msg, msgLen, signature, sigLen, pk);
  OQS_SIG_free(sig);

  return rc == OQS_SUCCESS;
}
