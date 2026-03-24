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

#include <oqs/oqs.h>

#include <rfb/PQCAlgorithm.h>

using namespace rfb;

const char* rfb::pqkemAlgOQSName(uint8_t algId)
{
  switch (algId) {
    case pqkemAlgMLKEM512:  return OQS_KEM_alg_ml_kem_512;
    case pqkemAlgMLKEM768:  return OQS_KEM_alg_ml_kem_768;
    case pqkemAlgMLKEM1024: return OQS_KEM_alg_ml_kem_1024;
    default: return nullptr;
  }
}

const char* rfb::pqkemAlgDisplayName(uint8_t algId)
{
  switch (algId) {
    case pqkemAlgMLKEM512:  return "ML-KEM-512";
    case pqkemAlgMLKEM768:  return "ML-KEM-768";
    case pqkemAlgMLKEM1024: return "ML-KEM-1024";
    default: return "Unknown";
  }
}

std::vector<uint8_t> rfb::pqkemProbeSupported()
{
  std::vector<uint8_t> supported;

  // Probe strongest first
  static const uint8_t candidates[] = {
    pqkemAlgMLKEM1024,
    pqkemAlgMLKEM768,
    pqkemAlgMLKEM512,
  };

  for (auto algId : candidates) {
    const char* oqsName = pqkemAlgOQSName(algId);
    if (oqsName) {
      OQS_KEM* kem = OQS_KEM_new(oqsName);
      if (kem) {
        supported.push_back(algId);
        OQS_KEM_free(kem);
      }
    }
  }

  return supported;
}
