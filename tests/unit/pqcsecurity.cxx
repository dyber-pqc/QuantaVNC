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
#include <rfb/SecurityServer.h>
#ifdef HAVE_LIBOQS
#include <rfb/PQCAlgorithm.h>
#include <rfb/PQCSignature.h>
#include <rfb/PQCKeyStore.h>
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

// --- ML-DSA Signature Algorithm Tests ---

TEST(PQCSignature, AlgorithmConstants) {
  EXPECT_EQ(rfb::pqdsaAlgMLDSA44, 1);
  EXPECT_EQ(rfb::pqdsaAlgMLDSA65, 2);
  EXPECT_EQ(rfb::pqdsaAlgMLDSA87, 3);
}

TEST(PQCSignature, OQSNameMapping) {
  EXPECT_NE(rfb::pqdsaAlgOQSName(rfb::pqdsaAlgMLDSA44), nullptr);
  EXPECT_NE(rfb::pqdsaAlgOQSName(rfb::pqdsaAlgMLDSA65), nullptr);
  EXPECT_NE(rfb::pqdsaAlgOQSName(rfb::pqdsaAlgMLDSA87), nullptr);
  EXPECT_EQ(rfb::pqdsaAlgOQSName(0), nullptr);
  EXPECT_EQ(rfb::pqdsaAlgOQSName(255), nullptr);
}

TEST(PQCSignature, DisplayNames) {
  EXPECT_STREQ(rfb::pqdsaAlgDisplayName(rfb::pqdsaAlgMLDSA44), "ML-DSA-44");
  EXPECT_STREQ(rfb::pqdsaAlgDisplayName(rfb::pqdsaAlgMLDSA65), "ML-DSA-65");
  EXPECT_STREQ(rfb::pqdsaAlgDisplayName(rfb::pqdsaAlgMLDSA87), "ML-DSA-87");
  EXPECT_STREQ(rfb::pqdsaAlgDisplayName(0), "Unknown");
}

TEST(PQCSignature, ProbeSupported) {
  auto supported = rfb::pqdsaProbeSupported();

  // liboqs should support at least ML-DSA-65
  EXPECT_FALSE(supported.empty());

  for (auto algId : supported) {
    EXPECT_NE(rfb::pqdsaAlgOQSName(algId), nullptr)
      << "Probed DSA algorithm ID " << (int)algId << " has no OQS name";
  }

  // Should be ordered strongest first (87, 65, 44)
  if (supported.size() >= 2) {
    for (size_t i = 0; i < supported.size() - 1; i++) {
      EXPECT_GT(supported[i], supported[i + 1])
        << "DSA algorithms not in strongest-first order";
    }
  }

  // ML-DSA-65 should always be available
  bool has65 = false;
  for (auto algId : supported) {
    if (algId == rfb::pqdsaAlgMLDSA65)
      has65 = true;
  }
  EXPECT_TRUE(has65) << "ML-DSA-65 not found in supported algorithms";
}

TEST(PQCSignature, SignAndVerify) {
  rfb::PQCKeyStore ks;
  ASSERT_TRUE(ks.generateForTest(rfb::pqdsaAlgMLDSA65));

  // Sign a test message
  const uint8_t msg[] = "QuantaVNC test message for ML-DSA signature";
  uint8_t* sig = nullptr;
  size_t sigLen = 0;
  ASSERT_TRUE(ks.sign(msg, sizeof(msg), &sig, &sigLen));
  EXPECT_GT(sigLen, 0u);

  // Verify the signature
  EXPECT_TRUE(rfb::PQCKeyStore::verify(
    rfb::pqdsaAlgMLDSA65,
    ks.getPublicKey(), ks.getPublicKeyLen(),
    msg, sizeof(msg), sig, sigLen));

  // Verify fails with wrong message
  const uint8_t wrongMsg[] = "Wrong message";
  EXPECT_FALSE(rfb::PQCKeyStore::verify(
    rfb::pqdsaAlgMLDSA65,
    ks.getPublicKey(), ks.getPublicKeyLen(),
    wrongMsg, sizeof(wrongMsg), sig, sigLen));

  delete[] sig;
}

TEST(PQCSignature, RejectWrongKey) {
  rfb::PQCKeyStore ks1, ks2;
  ASSERT_TRUE(ks1.loadOrGenerate("", rfb::pqdsaAlgMLDSA65));
  ASSERT_TRUE(ks2.loadOrGenerate("", rfb::pqdsaAlgMLDSA65));

  const uint8_t msg[] = "Test message";
  uint8_t* sig = nullptr;
  size_t sigLen = 0;
  ASSERT_TRUE(ks1.sign(msg, sizeof(msg), &sig, &sigLen));

  // Verify with wrong public key should fail
  EXPECT_FALSE(rfb::PQCKeyStore::verify(
    rfb::pqdsaAlgMLDSA65,
    ks2.getPublicKey(), ks2.getPublicKeyLen(),
    msg, sizeof(msg), sig, sigLen));

  delete[] sig;
}

TEST(PQCSignature, Fingerprint) {
  rfb::PQCKeyStore ks;
  ASSERT_TRUE(ks.generateForTest(rfb::pqdsaAlgMLDSA65));

  std::string fp = ks.computeFingerprint();
  EXPECT_FALSE(fp.empty());
  // Fingerprint format: xx:xx:xx:...:xx (32 bytes = 95 chars)
  EXPECT_EQ(fp.length(), 95u);
}

#endif // HAVE_LIBOQS

// --- PQCMode Tests ---

TEST(PQCMode, IsPQCType) {
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQKEMNone));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQKEMVnc));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQKEMPlain));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQTLSNone));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQTLSVnc));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQTLSPlain));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQX509None));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQX509Vnc));
  EXPECT_TRUE(rfb::SecurityServer::isPQCType(rfb::secTypePQX509Plain));

  // Non-PQC types
  EXPECT_FALSE(rfb::SecurityServer::isPQCType(rfb::secTypeNone));
  EXPECT_FALSE(rfb::SecurityServer::isPQCType(rfb::secTypeVncAuth));
  EXPECT_FALSE(rfb::SecurityServer::isPQCType(rfb::secTypePlain));
  EXPECT_FALSE(rfb::SecurityServer::isPQCType(rfb::secTypeTLSVnc));
  EXPECT_FALSE(rfb::SecurityServer::isPQCType(rfb::secTypeX509Vnc));
}
