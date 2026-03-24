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

#ifndef __PQC_ALGORITHM_H__
#define __PQC_ALGORITHM_H__

#ifndef HAVE_LIBOQS
#error "This header should not be included without HAVE_LIBOQS defined"
#endif

#include <stdint.h>
#include <vector>

namespace rfb {

  // PQC KEM Algorithm IDs for wire protocol negotiation.
  // Sent as U8 on the wire during PQKEM handshake.
  enum PQKEMAlgorithm : uint8_t {
    pqkemAlgMLKEM512  = 1,  // NIST Security Level 1
    pqkemAlgMLKEM768  = 2,  // NIST Security Level 3 (default)
    pqkemAlgMLKEM1024 = 3,  // NIST Security Level 5
  };

  // Returns the liboqs algorithm identifier string for the given algorithm ID,
  // e.g. OQS_KEM_alg_ml_kem_768. Returns nullptr if unknown.
  const char* pqkemAlgOQSName(uint8_t algId);

  // Returns a human-readable display name, e.g. "ML-KEM-768".
  // Returns "Unknown" if the algorithm ID is not recognized.
  const char* pqkemAlgDisplayName(uint8_t algId);

  // Probes liboqs at runtime and returns a list of supported algorithm IDs,
  // ordered from strongest to weakest (1024, 768, 512).
  std::vector<uint8_t> pqkemProbeSupported();

}

#endif
