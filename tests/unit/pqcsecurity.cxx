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

#include <gtest/gtest.h>

#include <rfb/Security.h>
#ifdef HAVE_LIBOQS
#include <rfb/PQCAlgorithm.h>
#endif

// Test that PQC security type constants are defined correctly
TEST(PQCSecurity, TypeConstants) {
  EXPECT_EQ(rfb::secTypePQKEMNone, 276);
  EXPECT_EQ(rfb::secTypePQKEMVnc, 277);
  EXPECT_EQ(rfb::secTypePQKEMPlain, 278);
  EXPECT_EQ(rfb::secTypePQTLSNone, 280);
  EXPECT_EQ(rfb::secTypePQTLSVnc, 281);
  EXPECT_EQ(rfb::secTypePQTLSPlain, 282);
  EXPECT_EQ(rfb::secTypePQX509None, 283);
  EXPECT_EQ(rfb::secTypePQX509Vnc, 284);
  EXPECT_EQ(rfb::secTypePQX509Plain, 285);
}

// Test that PQC types are VeNCrypt subtypes (>= 256)
TEST(PQCSecurity, AreVeNCryptSubtypes) {
  EXPECT_GE(rfb::secTypePQKEMNone, 256);
  EXPECT_GE(rfb::secTypePQKEMVnc, 256);
  EXPECT_GE(rfb::secTypePQKEMPlain, 256);
  EXPECT_GE(rfb::secTypePQTLSNone, 256);
  EXPECT_GE(rfb::secTypePQTLSVnc, 256);
  EXPECT_GE(rfb::secTypePQTLSPlain, 256);
  EXPECT_GE(rfb::secTypePQX509None, 256);
  EXPECT_GE(rfb::secTypePQX509Vnc, 256);
  EXPECT_GE(rfb::secTypePQX509Plain, 256);
}

// Test name-to-number mapping
TEST(PQCSecurity, SecTypeNum) {
  EXPECT_EQ(rfb::secTypeNum("PQKEMNone"), (uint32_t)rfb::secTypePQKEMNone);
  EXPECT_EQ(rfb::secTypeNum("PQKEMVnc"), (uint32_t)rfb::secTypePQKEMVnc);
  EXPECT_EQ(rfb::secTypeNum("PQKEMPlain"), (uint32_t)rfb::secTypePQKEMPlain);
  EXPECT_EQ(rfb::secTypeNum("PQTLSNone"), (uint32_t)rfb::secTypePQTLSNone);
  EXPECT_EQ(rfb::secTypeNum("PQTLSVnc"), (uint32_t)rfb::secTypePQTLSVnc);
  EXPECT_EQ(rfb::secTypeNum("PQTLSPlain"), (uint32_t)rfb::secTypePQTLSPlain);
  EXPECT_EQ(rfb::secTypeNum("PQX509None"), (uint32_t)rfb::secTypePQX509None);
  EXPECT_EQ(rfb::secTypeNum("PQX509Vnc"), (uint32_t)rfb::secTypePQX509Vnc);
  EXPECT_EQ(rfb::secTypeNum("PQX509Plain"), (uint32_t)rfb::secTypePQX509Plain);
}

// Test case-insensitive name-to-number mapping
TEST(PQCSecurity, SecTypeNumCaseInsensitive) {
  EXPECT_EQ(rfb::secTypeNum("pqkemnone"), (uint32_t)rfb::secTypePQKEMNone);
  EXPECT_EQ(rfb::secTypeNum("PQKEMVNC"), (uint32_t)rfb::secTypePQKEMVnc);
  EXPECT_EQ(rfb::secTypeNum("pqkemplain"), (uint32_t)rfb::secTypePQKEMPlain);
}

// Test number-to-name mapping
TEST(PQCSecurity, SecTypeName) {
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQKEMNone), "PQKEMNone");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQKEMVnc), "PQKEMVnc");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQKEMPlain), "PQKEMPlain");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQTLSNone), "PQTLSNone");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQTLSVnc), "PQTLSVnc");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQTLSPlain), "PQTLSPlain");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQX509None), "PQX509None");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQX509Vnc), "PQX509Vnc");
  EXPECT_STREQ(rfb::secTypeName(rfb::secTypePQX509Plain), "PQX509Plain");
}

// Test that PQC types do not clash with existing types
TEST(PQCSecurity, NoClashWithExistingTypes) {
  // Existing VeNCrypt types are 256-262
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypePlain);
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypeTLSNone);
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypeTLSVnc);
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypeTLSPlain);
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypeX509None);
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypeX509Vnc);
  EXPECT_NE(rfb::secTypePQKEMNone, rfb::secTypeX509Plain);
}

// Test Security class with PQC types
TEST(PQCSecurity, SecurityClassEnableDisable) {
  rfb::Security sec;

  sec.EnableSecType(rfb::secTypePQKEMVnc);
  EXPECT_TRUE(sec.IsSupported(rfb::secTypePQKEMVnc));

  // PQC types are VeNCrypt subtypes, so VeNCrypt should be in basic types
  auto basicTypes = sec.GetEnabledSecTypes();
  bool hasVeNCrypt = false;
  for (auto t : basicTypes) {
    if (t == rfb::secTypeVeNCrypt)
      hasVeNCrypt = true;
  }
  EXPECT_TRUE(hasVeNCrypt);

  // PQC type should be in extended types
  auto extTypes = sec.GetEnabledExtSecTypes();
  bool hasPQKEM = false;
  for (auto t : extTypes) {
    if (t == rfb::secTypePQKEMVnc)
      hasPQKEM = true;
  }
  EXPECT_TRUE(hasPQKEM);

  sec.DisableSecType(rfb::secTypePQKEMVnc);
  EXPECT_FALSE(sec.IsSupported(rfb::secTypePQKEMVnc));
}

// Test that all PQC types are distinct
TEST(PQCSecurity, AllTypesDistinct) {
  uint32_t types[] = {
    rfb::secTypePQKEMNone, rfb::secTypePQKEMVnc, rfb::secTypePQKEMPlain,
    rfb::secTypePQTLSNone, rfb::secTypePQTLSVnc, rfb::secTypePQTLSPlain,
    rfb::secTypePQX509None, rfb::secTypePQX509Vnc, rfb::secTypePQX509Plain,
  };
  for (size_t i = 0; i < 9; i++) {
    for (size_t j = i + 1; j < 9; j++) {
      EXPECT_NE(types[i], types[j])
        << "Types at index " << i << " and " << j << " clash";
    }
  }
}

// --- Algorithm Negotiation Tests ---

#ifdef HAVE_LIBOQS

TEST(PQCAlgorithm, AlgorithmIDConstants) {
  EXPECT_EQ(rfb::pqkemAlgMLKEM512, 1);
  EXPECT_EQ(rfb::pqkemAlgMLKEM768, 2);
  EXPECT_EQ(rfb::pqkemAlgMLKEM1024, 3);
}

TEST(PQCAlgorithm, OQSNameMapping) {
  // Valid algorithms return non-null liboqs strings
  EXPECT_NE(rfb::pqkemAlgOQSName(rfb::pqkemAlgMLKEM512), nullptr);
  EXPECT_NE(rfb::pqkemAlgOQSName(rfb::pqkemAlgMLKEM768), nullptr);
  EXPECT_NE(rfb::pqkemAlgOQSName(rfb::pqkemAlgMLKEM1024), nullptr);

  // Invalid algorithm returns null
  EXPECT_EQ(rfb::pqkemAlgOQSName(0), nullptr);
  EXPECT_EQ(rfb::pqkemAlgOQSName(255), nullptr);
}

TEST(PQCAlgorithm, DisplayNames) {
  EXPECT_STREQ(rfb::pqkemAlgDisplayName(rfb::pqkemAlgMLKEM512), "ML-KEM-512");
  EXPECT_STREQ(rfb::pqkemAlgDisplayName(rfb::pqkemAlgMLKEM768), "ML-KEM-768");
  EXPECT_STREQ(rfb::pqkemAlgDisplayName(rfb::pqkemAlgMLKEM1024), "ML-KEM-1024");
  EXPECT_STREQ(rfb::pqkemAlgDisplayName(0), "Unknown");
}

TEST(PQCAlgorithm, ProbeSupported) {
  auto supported = rfb::pqkemProbeSupported();

  // liboqs should support at least ML-KEM-768
  EXPECT_FALSE(supported.empty());

  // All returned IDs should be valid
  for (auto algId : supported) {
    EXPECT_NE(rfb::pqkemAlgOQSName(algId), nullptr)
      << "Probed algorithm ID " << (int)algId << " has no OQS name";
  }

  // Should be ordered strongest first (1024, 768, 512)
  if (supported.size() >= 2) {
    for (size_t i = 0; i < supported.size() - 1; i++) {
      EXPECT_GT(supported[i], supported[i + 1])
        << "Algorithms not in strongest-first order";
    }
  }

  // ML-KEM-768 should always be available
  bool has768 = false;
  for (auto algId : supported) {
    if (algId == rfb::pqkemAlgMLKEM768)
      has768 = true;
  }
  EXPECT_TRUE(has768) << "ML-KEM-768 not found in supported algorithms";
}

#endif // HAVE_LIBOQS
