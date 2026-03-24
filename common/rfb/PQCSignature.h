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

#ifndef __PQC_SIGNATURE_H__
#define __PQC_SIGNATURE_H__

#ifndef HAVE_LIBOQS
#error "This header should not be included without HAVE_LIBOQS defined"
#endif

#include <stdint.h>
#include <vector>

namespace rfb {

  // PQC Digital Signature Algorithm IDs for wire protocol.
  // Used for ML-DSA (FIPS 204) server authentication.
  enum PQDSAAlgorithm : uint8_t {
    pqdsaAlgMLDSA44 = 1,   // NIST Security Level 2
    pqdsaAlgMLDSA65 = 2,   // NIST Security Level 3 (default)
    pqdsaAlgMLDSA87 = 3,   // NIST Security Level 5
  };

  // Returns the liboqs algorithm identifier string for the given DSA algorithm ID.
  // Returns nullptr if unknown.
  const char* pqdsaAlgOQSName(uint8_t algId);

  // Returns a human-readable display name, e.g. "ML-DSA-65".
  const char* pqdsaAlgDisplayName(uint8_t algId);

  // Probes liboqs at runtime and returns a list of supported DSA algorithm IDs,
  // ordered from strongest to weakest (87, 65, 44).
  std::vector<uint8_t> pqdsaProbeSupported();

}

#endif
