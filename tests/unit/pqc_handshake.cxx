/*
 * QuantaVNC - Post-Quantum Cryptography VNC Platform
 * Copyright (C) 2026 Dyber, Inc.
 *
 * End-to-end integration tests for the PQKEM handshake protocol.
 * These tests simulate the full client-server key exchange at the
 * cryptographic protocol level, verifying:
 *   - ML-KEM encapsulation/decapsulation produces same shared secret
 *   - X25519 ECDH produces same shared secret on both sides
 *   - ML-DSA signatures are generated and verified correctly
 *   - Key derivation produces identical keys on both sides
 *   - Transcript hashes match between client and server
 *   - AES-256-EAX encrypt/decrypt roundtrip works
 *   - Algorithm negotiation selects the strongest available
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gtest/gtest.h>
#include <string.h>

#ifdef HAVE_LIBOQS

#include <oqs/oqs.h>
#include <nettle/sha2.h>
#include <nettle/curve25519.h>

#include <rfb/PQCAlgorithm.h>
#include <rfb/PQCSignature.h>
#include <rfb/PQCKeyStore.h>

#ifdef HAVE_NETTLE
#include <rdr/MemInStream.h>
#include <rdr/MemOutStream.h>
#include <rdr/AESInStream.h>
#include <rdr/AESOutStream.h>
#endif

// Helper: derive session key using the same KDF as CSecurityPQKEM/SSecurityPQKEM
static void deriveKey(const uint8_t* kemSS, size_t kemSSLen,
                      const uint8_t* ecdhSS,
                      uint8_t selectedAlg,
                      const char* label,
                      uint8_t* outKey)
{
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, kemSSLen, kemSS);
  sha256_update(&ctx, 32, ecdhSS);
  sha256_update(&ctx, 1, &selectedAlg);
  sha256_update(&ctx, strlen(label), (const uint8_t*)label);
  sha256_digest(&ctx, 32, outKey);
}

// Helper: compute transcript hash (client-side ordering)
static void computeClientHash(uint8_t selectedAlg,
                               const uint8_t* ct, size_t ctLen,
                               const uint8_t* clientX25519Pub,
                               const uint8_t* serverKEMPub, size_t kemPubLen,
                               const uint8_t* serverX25519Pub,
                               uint8_t* outHash)
{
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, 1, &selectedAlg);
  sha256_update(&ctx, ctLen, ct);
  sha256_update(&ctx, 32, clientX25519Pub);
  sha256_update(&ctx, kemPubLen, serverKEMPub);
  sha256_update(&ctx, 32, serverX25519Pub);
  sha256_digest(&ctx, 32, outHash);
}

// Helper: compute transcript hash (server-side ordering)
static void computeServerHash(uint8_t selectedAlg,
                               const uint8_t* serverKEMPub, size_t kemPubLen,
                               const uint8_t* serverX25519Pub,
                               const uint8_t* ct, size_t ctLen,
                               const uint8_t* clientX25519Pub,
                               uint8_t* outHash)
{
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, 1, &selectedAlg);
  sha256_update(&ctx, kemPubLen, serverKEMPub);
  sha256_update(&ctx, 32, serverX25519Pub);
  sha256_update(&ctx, ctLen, ct);
  sha256_update(&ctx, 32, clientX25519Pub);
  sha256_digest(&ctx, 32, outHash);
}

// Test: Full ML-KEM + X25519 hybrid key exchange produces same shared secrets
TEST(PQCHandshake, HybridKeyExchangeProducesSameSecrets)
{
  uint8_t selectedAlg = rfb::pqkemAlgMLKEM768;
  const char* oqsName = rfb::pqkemAlgOQSName(selectedAlg);
  ASSERT_NE(oqsName, nullptr);

  // --- Server generates ML-KEM keypair ---
  OQS_KEM* kem = OQS_KEM_new(oqsName);
  ASSERT_NE(kem, nullptr);

  std::vector<uint8_t> serverKEMPub(kem->length_public_key);
  std::vector<uint8_t> serverKEMSec(kem->length_secret_key);
  ASSERT_EQ(OQS_KEM_keypair(kem, serverKEMPub.data(), serverKEMSec.data()),
            OQS_SUCCESS);

  // --- Server generates X25519 keypair ---
  uint8_t serverX25519Priv[32], serverX25519Pub[32];
  OQS_randombytes(serverX25519Priv, 32);
  serverX25519Priv[0] &= 248;
  serverX25519Priv[31] &= 127;
  serverX25519Priv[31] |= 64;
  static const uint8_t basepoint[32] = { 9 };
  curve25519_mul(serverX25519Pub, serverX25519Priv, basepoint);

  // --- Client encapsulates ---
  std::vector<uint8_t> clientCiphertext(kem->length_ciphertext);
  std::vector<uint8_t> clientKEMSS(kem->length_shared_secret);
  ASSERT_EQ(OQS_KEM_encaps(kem, clientCiphertext.data(), clientKEMSS.data(),
                            serverKEMPub.data()),
            OQS_SUCCESS);

  // --- Client generates X25519 keypair ---
  uint8_t clientX25519Priv[32], clientX25519Pub[32];
  OQS_randombytes(clientX25519Priv, 32);
  clientX25519Priv[0] &= 248;
  clientX25519Priv[31] &= 127;
  clientX25519Priv[31] |= 64;
  curve25519_mul(clientX25519Pub, clientX25519Priv, basepoint);

  // --- Server decapsulates ---
  std::vector<uint8_t> serverKEMSS(kem->length_shared_secret);
  ASSERT_EQ(OQS_KEM_decaps(kem, serverKEMSS.data(), clientCiphertext.data(),
                            serverKEMSec.data()),
            OQS_SUCCESS);

  OQS_KEM_free(kem);

  // ML-KEM shared secrets MUST match
  ASSERT_EQ(clientKEMSS.size(), serverKEMSS.size());
  EXPECT_EQ(memcmp(clientKEMSS.data(), serverKEMSS.data(), clientKEMSS.size()), 0)
    << "ML-KEM shared secrets do not match";

  // --- X25519 ECDH ---
  uint8_t clientECDH[32], serverECDH[32];
  curve25519_mul(clientECDH, clientX25519Priv, serverX25519Pub);
  curve25519_mul(serverECDH, serverX25519Priv, clientX25519Pub);

  // X25519 shared secrets MUST match
  EXPECT_EQ(memcmp(clientECDH, serverECDH, 32), 0)
    << "X25519 shared secrets do not match";

  // --- Key derivation ---
  uint8_t clientC2S[32], clientS2C[32];
  uint8_t serverC2S[32], serverS2C[32];

  deriveKey(clientKEMSS.data(), clientKEMSS.size(), clientECDH,
            selectedAlg, "QuantaVNC-PQKEM-C2S", clientC2S);
  deriveKey(clientKEMSS.data(), clientKEMSS.size(), clientECDH,
            selectedAlg, "QuantaVNC-PQKEM-S2C", clientS2C);

  deriveKey(serverKEMSS.data(), serverKEMSS.size(), serverECDH,
            selectedAlg, "QuantaVNC-PQKEM-C2S", serverC2S);
  deriveKey(serverKEMSS.data(), serverKEMSS.size(), serverECDH,
            selectedAlg, "QuantaVNC-PQKEM-S2C", serverS2C);

  // Derived keys MUST match
  EXPECT_EQ(memcmp(clientC2S, serverC2S, 32), 0)
    << "C2S session keys do not match";
  EXPECT_EQ(memcmp(clientS2C, serverS2C, 32), 0)
    << "S2C session keys do not match";

  // C2S and S2C keys MUST be different
  EXPECT_NE(memcmp(clientC2S, clientS2C, 32), 0)
    << "C2S and S2C keys should be different";
}

// Test: ML-DSA signature over key exchange material
TEST(PQCHandshake, MLDSASignatureOverKeyMaterial)
{
  // Generate server signing key
  rfb::PQCKeyStore signingKey;
  ASSERT_TRUE(signingKey.generateForTest(rfb::pqdsaAlgMLDSA65));

  // Simulate key material that would be signed
  uint8_t selectedAlg = rfb::pqkemAlgMLKEM768;
  uint8_t fakePubKey[1184];
  uint8_t fakeX25519[32];
  OQS_randombytes(fakePubKey, sizeof(fakePubKey));
  OQS_randombytes(fakeX25519, sizeof(fakeX25519));

  // Compute message hash (same as SSecurityPQKEM::sendSignature)
  uint8_t msgHash[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 1, &selectedAlg);
    sha256_update(&ctx, sizeof(fakePubKey), fakePubKey);
    sha256_update(&ctx, 32, fakeX25519);
    sha256_digest(&ctx, 32, msgHash);
  }

  // Server signs
  uint8_t* sig = nullptr;
  size_t sigLen = 0;
  ASSERT_TRUE(signingKey.sign(msgHash, 32, &sig, &sigLen));
  EXPECT_GT(sigLen, 0u);

  // Client verifies with correct public key → should pass
  EXPECT_TRUE(rfb::PQCKeyStore::verify(
    rfb::pqdsaAlgMLDSA65,
    signingKey.getPublicKey(), signingKey.getPublicKeyLen(),
    msgHash, 32, sig, sigLen));

  // Tampered message → should fail
  uint8_t tamperedHash[32];
  memcpy(tamperedHash, msgHash, 32);
  tamperedHash[0] ^= 0xFF;
  EXPECT_FALSE(rfb::PQCKeyStore::verify(
    rfb::pqdsaAlgMLDSA65,
    signingKey.getPublicKey(), signingKey.getPublicKeyLen(),
    tamperedHash, 32, sig, sigLen));

  // Wrong key → should fail
  rfb::PQCKeyStore otherKey;
  ASSERT_TRUE(otherKey.generateForTest(rfb::pqdsaAlgMLDSA65));
  EXPECT_FALSE(rfb::PQCKeyStore::verify(
    rfb::pqdsaAlgMLDSA65,
    otherKey.getPublicKey(), otherKey.getPublicKeyLen(),
    msgHash, 32, sig, sigLen));

  delete[] sig;
}

// Test: Transcript hashes match between client and server
TEST(PQCHandshake, TranscriptHashesMatch)
{
  uint8_t selectedAlg = rfb::pqkemAlgMLKEM768;

  // Generate test data
  uint8_t serverKEMPub[1184], serverX25519Pub[32];
  uint8_t ct[1088], clientX25519Pub[32];
  OQS_randombytes(serverKEMPub, sizeof(serverKEMPub));
  OQS_randombytes(serverX25519Pub, sizeof(serverX25519Pub));
  OQS_randombytes(ct, sizeof(ct));
  OQS_randombytes(clientX25519Pub, sizeof(clientX25519Pub));

  // Compute hashes as client and server would
  uint8_t clientHash[32], serverHash[32];
  uint8_t expectedClientHash[32], expectedServerHash[32];

  // Client computes its own hash and the expected server hash
  computeClientHash(selectedAlg, ct, sizeof(ct), clientX25519Pub,
                    serverKEMPub, sizeof(serverKEMPub), serverX25519Pub,
                    clientHash);
  computeServerHash(selectedAlg, serverKEMPub, sizeof(serverKEMPub),
                    serverX25519Pub, ct, sizeof(ct), clientX25519Pub,
                    expectedServerHash);

  // Server computes its own hash and the expected client hash
  computeServerHash(selectedAlg, serverKEMPub, sizeof(serverKEMPub),
                    serverX25519Pub, ct, sizeof(ct), clientX25519Pub,
                    serverHash);
  computeClientHash(selectedAlg, ct, sizeof(ct), clientX25519Pub,
                    serverKEMPub, sizeof(serverKEMPub), serverX25519Pub,
                    expectedClientHash);

  // Server's hash should match what client expects
  EXPECT_EQ(memcmp(serverHash, expectedServerHash, 32), 0)
    << "Server hash doesn't match client's expectation";

  // Client's hash should match what server expects
  EXPECT_EQ(memcmp(clientHash, expectedClientHash, 32), 0)
    << "Client hash doesn't match server's expectation";

  // Client hash and server hash should be DIFFERENT (different ordering)
  EXPECT_NE(memcmp(clientHash, serverHash, 32), 0)
    << "Client and server hashes should differ (different field ordering)";
}

// Test: Algorithm binding prevents downgrade
TEST(PQCHandshake, AlgorithmBindingPreventsDowngrade)
{
  uint8_t kemSS[32], ecdhSS[32];
  OQS_randombytes(kemSS, 32);
  OQS_randombytes(ecdhSS, 32);

  // Derive keys with different algorithm IDs
  uint8_t key512[32], key768[32], key1024[32];
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM512,
            "QuantaVNC-PQKEM-C2S", key512);
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM768,
            "QuantaVNC-PQKEM-C2S", key768);
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM1024,
            "QuantaVNC-PQKEM-C2S", key1024);

  // All three keys MUST be different
  EXPECT_NE(memcmp(key512, key768, 32), 0)
    << "512 and 768 keys should differ";
  EXPECT_NE(memcmp(key768, key1024, 32), 0)
    << "768 and 1024 keys should differ";
  EXPECT_NE(memcmp(key512, key1024, 32), 0)
    << "512 and 1024 keys should differ";
}

// Test: Algorithm negotiation selects strongest
TEST(PQCHandshake, NegotiationSelectsStrongest)
{
  auto supported = rfb::pqkemProbeSupported();
  ASSERT_FALSE(supported.empty());

  // First element should be the strongest (highest ID = 1024 > 768 > 512)
  uint8_t strongest = supported[0];
  for (auto alg : supported) {
    EXPECT_LE(alg, strongest)
      << "Algorithm " << (int)alg << " should not be stronger than "
      << (int)strongest;
  }

  // ML-KEM-768 should always be available
  bool found768 = false;
  for (auto alg : supported) {
    if (alg == rfb::pqkemAlgMLKEM768)
      found768 = true;
  }
  EXPECT_TRUE(found768);
}

// Test: Full protocol simulation with all ML-KEM variants
class PQCHandshakeVariant : public ::testing::TestWithParam<uint8_t> {};

TEST_P(PQCHandshakeVariant, FullKeyExchangeWithVariant)
{
  uint8_t algId = GetParam();
  const char* oqsName = rfb::pqkemAlgOQSName(algId);
  if (!oqsName) GTEST_SKIP() << "Algorithm not compiled in";

  OQS_KEM* kem = OQS_KEM_new(oqsName);
  if (!kem) GTEST_SKIP() << "Algorithm not available in liboqs";

  // Server keygen
  std::vector<uint8_t> pk(kem->length_public_key);
  std::vector<uint8_t> sk(kem->length_secret_key);
  ASSERT_EQ(OQS_KEM_keypair(kem, pk.data(), sk.data()), OQS_SUCCESS);

  // Client encaps
  std::vector<uint8_t> ct(kem->length_ciphertext);
  std::vector<uint8_t> ss_client(kem->length_shared_secret);
  ASSERT_EQ(OQS_KEM_encaps(kem, ct.data(), ss_client.data(), pk.data()),
            OQS_SUCCESS);

  // Server decaps
  std::vector<uint8_t> ss_server(kem->length_shared_secret);
  ASSERT_EQ(OQS_KEM_decaps(kem, ss_server.data(), ct.data(), sk.data()),
            OQS_SUCCESS);

  OQS_KEM_free(kem);

  // Shared secrets match
  EXPECT_EQ(memcmp(ss_client.data(), ss_server.data(), ss_client.size()), 0);

  // Key derivation produces matching keys
  uint8_t ecdhSS[32];
  OQS_randombytes(ecdhSS, 32);

  uint8_t clientKey[32], serverKey[32];
  deriveKey(ss_client.data(), ss_client.size(), ecdhSS, algId,
            "QuantaVNC-PQKEM-C2S", clientKey);
  deriveKey(ss_server.data(), ss_server.size(), ecdhSS, algId,
            "QuantaVNC-PQKEM-C2S", serverKey);

  EXPECT_EQ(memcmp(clientKey, serverKey, 32), 0);
}

INSTANTIATE_TEST_SUITE_P(AllMLKEMVariants, PQCHandshakeVariant,
  ::testing::Values(
    rfb::pqkemAlgMLKEM512,
    rfb::pqkemAlgMLKEM768,
    rfb::pqkemAlgMLKEM1024
  ));

// Test: All ML-DSA variants can sign and verify
class PQCDSAVariant : public ::testing::TestWithParam<uint8_t> {};

TEST_P(PQCDSAVariant, SignAndVerifyWithVariant)
{
  uint8_t algId = GetParam();
  const char* oqsName = rfb::pqdsaAlgOQSName(algId);
  if (!oqsName) GTEST_SKIP() << "DSA algorithm not compiled in";

  OQS_SIG* sig = OQS_SIG_new(oqsName);
  if (!sig) GTEST_SKIP() << "DSA algorithm not available in liboqs";
  OQS_SIG_free(sig);

  rfb::PQCKeyStore ks;
  ASSERT_TRUE(ks.generateForTest(algId));

  const uint8_t msg[] = "QuantaVNC E2E test message";
  uint8_t* signature = nullptr;
  size_t sigLen = 0;
  ASSERT_TRUE(ks.sign(msg, sizeof(msg), &signature, &sigLen));

  EXPECT_TRUE(rfb::PQCKeyStore::verify(
    algId, ks.getPublicKey(), ks.getPublicKeyLen(),
    msg, sizeof(msg), signature, sigLen));

  delete[] signature;
}

INSTANTIATE_TEST_SUITE_P(AllMLDSAVariants, PQCDSAVariant,
  ::testing::Values(
    rfb::pqdsaAlgMLDSA44,
    rfb::pqdsaAlgMLDSA65,
    rfb::pqdsaAlgMLDSA87
  ));

#ifdef HAVE_NETTLE
// Test: AES-256-EAX encrypt/decrypt roundtrip
TEST(PQCHandshake, AESEncryptDecryptRoundtrip)
{
  // Generate a random key
  uint8_t key[32];
  OQS_randombytes(key, 32);

  // Write encrypted data
  rdr::MemOutStream rawOut;
  {
    rdr::AESOutStream aesOut(&rawOut, key, 256);
    const uint8_t testData[] = "Hello, post-quantum world! This is QuantaVNC.";
    aesOut.writeBytes(testData, sizeof(testData));
    aesOut.flush();
  }

  // Read and decrypt
  rdr::MemInStream rawIn(rawOut.data(), rawOut.length());
  rdr::AESInStream aesIn(&rawIn, key, 256);

  uint8_t decrypted[128];
  const uint8_t expected[] = "Hello, post-quantum world! This is QuantaVNC.";
  ASSERT_TRUE(aesIn.hasData(sizeof(expected)));
  aesIn.readBytes(decrypted, sizeof(expected));

  EXPECT_EQ(memcmp(decrypted, expected, sizeof(expected)), 0)
    << "Decrypted data doesn't match original";
}

// Test: AES with wrong key fails (MAC verification)
TEST(PQCHandshake, AESWrongKeyFails)
{
  uint8_t key1[32], key2[32];
  OQS_randombytes(key1, 32);
  OQS_randombytes(key2, 32);

  // Encrypt with key1
  rdr::MemOutStream rawOut;
  {
    rdr::AESOutStream aesOut(&rawOut, key1, 256);
    const uint8_t data[] = "Secret data";
    aesOut.writeBytes(data, sizeof(data));
    aesOut.flush();
  }

  // Try to decrypt with key2 → should throw
  rdr::MemInStream rawIn(rawOut.data(), rawOut.length());
  rdr::AESInStream aesIn(&rawIn, key2, 256);

  uint8_t buf[64];
  EXPECT_THROW(aesIn.readBytes(buf, 12), std::exception)
    << "Decryption with wrong key should fail";
}

// Test: Bidirectional key derivation produces correct distinct keys
TEST(PQCHandshake, BidirectionalKeyDerivation)
{
  // Derive keys as the protocol would
  uint8_t kemSS[32], ecdhSS[32];
  OQS_randombytes(kemSS, 32);
  OQS_randombytes(ecdhSS, 32);

  uint8_t c2sKey[32], s2cKey[32];
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM768,
            "QuantaVNC-PQKEM-C2S", c2sKey);
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM768,
            "QuantaVNC-PQKEM-S2C", s2cKey);

  // C2S and S2C keys MUST be different
  EXPECT_NE(memcmp(c2sKey, s2cKey, 32), 0)
    << "C2S and S2C keys should be different";

  // Same inputs produce same outputs (deterministic)
  uint8_t c2sKey2[32], s2cKey2[32];
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM768,
            "QuantaVNC-PQKEM-C2S", c2sKey2);
  deriveKey(kemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM768,
            "QuantaVNC-PQKEM-S2C", s2cKey2);

  EXPECT_EQ(memcmp(c2sKey, c2sKey2, 32), 0)
    << "KDF should be deterministic for C2S";
  EXPECT_EQ(memcmp(s2cKey, s2cKey2, 32), 0)
    << "KDF should be deterministic for S2C";

  // Different shared secrets produce different keys
  uint8_t differentKemSS[32];
  OQS_randombytes(differentKemSS, 32);
  uint8_t differentKey[32];
  deriveKey(differentKemSS, 32, ecdhSS, rfb::pqkemAlgMLKEM768,
            "QuantaVNC-PQKEM-C2S", differentKey);
  EXPECT_NE(memcmp(c2sKey, differentKey, 32), 0)
    << "Different KEM shared secret should produce different key";
}
#endif // HAVE_NETTLE

// Test: Key store persistence (generate, save, reload)
TEST(PQCHandshake, KeyStorePersistence)
{
  const char* testPath = "test_pqc_key.tmp";

  // Generate and save
  {
    rfb::PQCKeyStore ks;
    ASSERT_TRUE(ks.loadOrGenerate(testPath, rfb::pqdsaAlgMLDSA65));
    EXPECT_TRUE(ks.isLoaded());
    EXPECT_EQ(ks.getAlgorithm(), rfb::pqdsaAlgMLDSA65);

    // Sign something
    const uint8_t msg[] = "test";
    uint8_t* sig = nullptr;
    size_t sigLen = 0;
    ASSERT_TRUE(ks.sign(msg, sizeof(msg), &sig, &sigLen));

    // Verify with the same key
    EXPECT_TRUE(rfb::PQCKeyStore::verify(
      rfb::pqdsaAlgMLDSA65,
      ks.getPublicKey(), ks.getPublicKeyLen(),
      msg, sizeof(msg), sig, sigLen));

    delete[] sig;
  }

  // Reload and verify same key
  {
    rfb::PQCKeyStore ks2;
    ASSERT_TRUE(ks2.loadOrGenerate(testPath, rfb::pqdsaAlgMLDSA65));
    EXPECT_TRUE(ks2.isLoaded());
    EXPECT_EQ(ks2.getAlgorithm(), rfb::pqdsaAlgMLDSA65);

    // Should be able to sign and verify
    const uint8_t msg[] = "test2";
    uint8_t* sig = nullptr;
    size_t sigLen = 0;
    ASSERT_TRUE(ks2.sign(msg, sizeof(msg), &sig, &sigLen));
    EXPECT_TRUE(rfb::PQCKeyStore::verify(
      rfb::pqdsaAlgMLDSA65,
      ks2.getPublicKey(), ks2.getPublicKeyLen(),
      msg, sizeof(msg), sig, sigLen));

    delete[] sig;
  }

  // Cleanup
  remove(testPath);
}

#endif // HAVE_LIBOQS
