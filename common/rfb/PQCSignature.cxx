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

#include <rfb/PQCSignature.h>

using namespace rfb;

const char* rfb::pqdsaAlgOQSName(uint8_t algId)
{
  switch (algId) {
    case pqdsaAlgMLDSA44: return OQS_SIG_alg_ml_dsa_44;
    case pqdsaAlgMLDSA65: return OQS_SIG_alg_ml_dsa_65;
    case pqdsaAlgMLDSA87: return OQS_SIG_alg_ml_dsa_87;
    default: return nullptr;
  }
}

const char* rfb::pqdsaAlgDisplayName(uint8_t algId)
{
  switch (algId) {
    case pqdsaAlgMLDSA44: return "ML-DSA-44";
    case pqdsaAlgMLDSA65: return "ML-DSA-65";
    case pqdsaAlgMLDSA87: return "ML-DSA-87";
    default: return "Unknown";
  }
}

std::vector<uint8_t> rfb::pqdsaProbeSupported()
{
  std::vector<uint8_t> supported;

  // Probe strongest first
  static const uint8_t candidates[] = {
    pqdsaAlgMLDSA87,
    pqdsaAlgMLDSA65,
    pqdsaAlgMLDSA44,
  };

  for (auto algId : candidates) {
    const char* oqsName = pqdsaAlgOQSName(algId);
    if (oqsName) {
      OQS_SIG* sig = OQS_SIG_new(oqsName);
      if (sig) {
        supported.push_back(algId);
        OQS_SIG_free(sig);
      }
    }
  }

  return supported;
}
