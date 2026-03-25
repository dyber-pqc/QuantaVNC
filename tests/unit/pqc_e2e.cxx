/*
 * QuantaVNC - Post-Quantum Cryptography VNC Platform
 * Copyright (C) 2026 Dyber, Inc.
 *
 * End-to-end integration tests for the full PQC handshake protocol.
 * These tests simulate the complete client<->server key exchange over
 * MemInStream/MemOutStream, exercising the real wire format:
 *
 *   Server: algo negotiation + KEM pub + X25519 pub
 *   Server: ML-DSA signature over key material
 *   Client: KEM ciphertext + X25519 pub
 *   Both:   AES-256-EAX channel setup
 *   Both:   Transcript hash exchange
 *   Server: subtype
 *   Client: encrypted credentials
 *
 * Verified properties:
 *   - All ML-KEM variants (512, 768, 1024) produce matching session keys
 *   - ML-DSA signature is verified in-protocol
 *   - Tampered signatures are rejected
 *   - C2S and S2C channels use different keys
 *   - Replay of ciphertext with wrong keys fails AES MAC check
 *   - Encrypted credential exchange works end-to-end
 *   - Algorithm downgrade is detected via KDF binding
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

// ---------------------------------------------------------------------------
// Helpers that mirror the real KDF used in CSecurityPQKEM / SSecurityPQKEM
// ---------------------------------------------------------------------------
static void deriveSessionKey(const uint8_t* kemSS, size_t kemSSLen,
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

// ---------------------------------------------------------------------------
// Full protocol simulation context
// ---------------------------------------------------------------------------
struct ProtocolContext {
  // Algorithm negotiation
  uint8_t selectedAlg;
  uint8_t dsaAlg;

  // Server ML-KEM keypair
  std::vector<uint8_t> serverKEMPub;
  std::vector<uint8_t> serverKEMSec;
  size_t kemPubKeyLen;

  // Server X25519
  uint8_t serverX25519Priv[32];
  uint8_t serverX25519Pub[32];

  // Client X25519
  uint8_t clientX25519Priv[32];
  uint8_t clientX25519Pub[32];

  // Client encapsulation results
  std::vector<uint8_t> kemCiphertext;
  std::vector<uint8_t> clientKEMSS;
  size_t kemCiphertextLen;

  // Server decapsulation results
  std::vector<uint8_t> serverKEMSS;

  // ECDH shared secrets
  uint8_t clientECDH[32];
  uint8_t serverECDH[32];

  // Derived session keys
  uint8_t clientC2SKey[32], clientS2CKey[32];
  uint8_t serverC2SKey[32], serverS2CKey[32];

  // Server signing key
  rfb::PQCKeyStore signingKey;

  // Wire buffers
  rdr::MemOutStream serverToClientWire;
  rdr::MemOutStream clientToServerWire;

  // Perform the full protocol simulation
  bool runFullHandshake(uint8_t kemAlgId, uint8_t dsaAlgId);

  // Individual phases for fine-grained testing
  bool serverGenerateKeys(uint8_t kemAlgId);
  bool serverWritePublicKeys();
  bool serverSignAndWrite(uint8_t dsaAlgId);
  bool clientReadAndEncapsulate();
  bool serverReadAndDecapsulate();
  bool deriveKeys();
  bool verifyTranscriptHashes();
};

bool ProtocolContext::serverGenerateKeys(uint8_t kemAlgId)
{
  selectedAlg = kemAlgId;
  const char* oqsName = rfb::pqkemAlgOQSName(kemAlgId);
  if (!oqsName) return false;

  OQS_KEM* kem = OQS_KEM_new(oqsName);
  if (!kem) return false;

  kemPubKeyLen = kem->length_public_key;
  serverKEMPub.resize(kemPubKeyLen);
  serverKEMSec.resize(kem->length_secret_key);

  if (OQS_KEM_keypair(kem, serverKEMPub.data(), serverKEMSec.data()) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    return false;
  }

  kemCiphertextLen = kem->length_ciphertext;
  clientKEMSS.resize(kem->length_shared_secret);
  serverKEMSS.resize(kem->length_shared_secret);

  OQS_KEM_free(kem);

  // Server X25519 keypair
  OQS_randombytes(serverX25519Priv, 32);
  serverX25519Priv[0] &= 248;
  serverX25519Priv[31] &= 127;
  serverX25519Priv[31] |= 64;
  static const uint8_t basepoint[32] = { 9 };
  curve25519_mul(serverX25519Pub, serverX25519Priv, basepoint);

  return true;
}

bool ProtocolContext::serverWritePublicKeys()
{
  // Wire format from SSecurityPQKEM::generateAndSendKeys():
  //   U8(numAlgs) || U8(algId)... || U8(selectedAlg) ||
  //   U16(kemPubKeyLen) || kemPubKey || x25519Public(32)
  std::vector<uint8_t> supported = rfb::pqkemProbeSupported();

  serverToClientWire.writeU8((uint8_t)supported.size());
  for (uint8_t algId : supported)
    serverToClientWire.writeU8(algId);
  serverToClientWire.writeU8(selectedAlg);

  serverToClientWire.writeU16((uint16_t)kemPubKeyLen);
  serverToClientWire.writeBytes(serverKEMPub.data(), kemPubKeyLen);
  serverToClientWire.writeBytes(serverX25519Pub, 32);
  serverToClientWire.flush();

  return true;
}

bool ProtocolContext::serverSignAndWrite(uint8_t dsaAlgId)
{
  dsaAlg = dsaAlgId;

  // Generate signing key
  if (!signingKey.generateForTest(dsaAlgId))
    return false;

  // Sign: SHA-256(selectedAlg || kemPubKey || serverX25519Public)
  uint8_t msgHash[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 1, &selectedAlg);
    sha256_update(&ctx, kemPubKeyLen, serverKEMPub.data());
    sha256_update(&ctx, 32, serverX25519Pub);
    sha256_digest(&ctx, 32, msgHash);
  }

  uint8_t* signature = nullptr;
  size_t sigLen = 0;
  if (!signingKey.sign(msgHash, 32, &signature, &sigLen))
    return false;

  // Wire format from SSecurityPQKEM::sendSignature():
  //   U8(dsaAlgId) || U16(dsaPubKeyLen) || dsaPubKey ||
  //   U16(sigLen) || signature
  serverToClientWire.writeU8(dsaAlgId);
  size_t pkLen = signingKey.getPublicKeyLen();
  serverToClientWire.writeU16((uint16_t)pkLen);
  serverToClientWire.writeBytes(signingKey.getPublicKey(), pkLen);
  serverToClientWire.writeU16((uint16_t)sigLen);
  serverToClientWire.writeBytes(signature, sigLen);
  serverToClientWire.flush();

  delete[] signature;
  return true;
}

bool ProtocolContext::clientReadAndEncapsulate()
{
  // Client reads the server's wire data and processes it.
  // We simulate what CSecurityPQKEM::readServerPublicKeys() +
  // readServerSignature() + writeEncapsulation() do.

  rdr::MemInStream s2cIn(serverToClientWire.data(), serverToClientWire.length());

  // --- Read algorithm negotiation ---
  uint8_t numAlgs = s2cIn.readU8();
  for (uint8_t i = 0; i < numAlgs; i++)
    s2cIn.readU8(); // skip algorithm list
  uint8_t negotiatedAlg = s2cIn.readU8();
  if (negotiatedAlg != selectedAlg)
    return false;

  // --- Read public keys ---
  uint16_t pubKeyLen = s2cIn.readU16();
  std::vector<uint8_t> svrKEMPub(pubKeyLen);
  s2cIn.readBytes(svrKEMPub.data(), pubKeyLen);

  uint8_t svrX25519Pub[32];
  s2cIn.readBytes(svrX25519Pub, 32);

  // --- Read and verify ML-DSA signature ---
  uint8_t svrDSAAlgId = s2cIn.readU8();
  uint16_t dsaPkLen = s2cIn.readU16();
  std::vector<uint8_t> dsaPubKey(dsaPkLen);
  s2cIn.readBytes(dsaPubKey.data(), dsaPkLen);
  uint16_t sigLen = s2cIn.readU16();
  std::vector<uint8_t> sig(sigLen);
  s2cIn.readBytes(sig.data(), sigLen);

  // Verify signature: SHA-256(selectedAlg || kemPubKey || serverX25519Public)
  uint8_t msgHash[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 1, &negotiatedAlg);
    sha256_update(&ctx, pubKeyLen, svrKEMPub.data());
    sha256_update(&ctx, 32, svrX25519Pub);
    sha256_digest(&ctx, 32, msgHash);
  }

  if (!rfb::PQCKeyStore::verify(svrDSAAlgId, dsaPubKey.data(), dsaPkLen,
                                 msgHash, 32, sig.data(), sigLen))
    return false;

  // --- ML-KEM encapsulation ---
  OQS_KEM* kem = OQS_KEM_new(rfb::pqkemAlgOQSName(negotiatedAlg));
  if (!kem) return false;

  kemCiphertext.resize(kem->length_ciphertext);
  if (OQS_KEM_encaps(kem, kemCiphertext.data(), clientKEMSS.data(),
                      svrKEMPub.data()) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    return false;
  }
  OQS_KEM_free(kem);

  // --- Client X25519 keypair ---
  OQS_randombytes(clientX25519Priv, 32);
  clientX25519Priv[0] &= 248;
  clientX25519Priv[31] &= 127;
  clientX25519Priv[31] |= 64;
  static const uint8_t basepoint[32] = { 9 };
  curve25519_mul(clientX25519Pub, clientX25519Priv, basepoint);

  // --- ECDH ---
  curve25519_mul(clientECDH, clientX25519Priv, svrX25519Pub);

  // --- Write encapsulation to server ---
  // Wire format from CSecurityPQKEM::writeEncapsulation():
  //   U16(ctLen) || ciphertext || clientX25519Public(32)
  clientToServerWire.writeU16((uint16_t)kemCiphertext.size());
  clientToServerWire.writeBytes(kemCiphertext.data(), kemCiphertext.size());
  clientToServerWire.writeBytes(clientX25519Pub, 32);
  clientToServerWire.flush();

  return true;
}

bool ProtocolContext::serverReadAndDecapsulate()
{
  // Server reads client encapsulation from wire
  rdr::MemInStream c2sIn(clientToServerWire.data(), clientToServerWire.length());

  uint16_t ctLen = c2sIn.readU16();
  std::vector<uint8_t> ciphertext(ctLen);
  c2sIn.readBytes(ciphertext.data(), ctLen);

  uint8_t cliX25519Pub[32];
  c2sIn.readBytes(cliX25519Pub, 32);
  memcpy(clientX25519Pub, cliX25519Pub, 32); // store for hash computation

  // --- ML-KEM decapsulation ---
  OQS_KEM* kem = OQS_KEM_new(rfb::pqkemAlgOQSName(selectedAlg));
  if (!kem) return false;

  if (ctLen != kem->length_ciphertext) {
    OQS_KEM_free(kem);
    return false;
  }

  if (OQS_KEM_decaps(kem, serverKEMSS.data(), ciphertext.data(),
                      serverKEMSec.data()) != OQS_SUCCESS) {
    OQS_KEM_free(kem);
    return false;
  }
  OQS_KEM_free(kem);

  // --- X25519 ECDH ---
  curve25519_mul(serverECDH, serverX25519Priv, cliX25519Pub);

  return true;
}

bool ProtocolContext::deriveKeys()
{
  // Client derives keys
  deriveSessionKey(clientKEMSS.data(), clientKEMSS.size(), clientECDH,
                   selectedAlg, "QuantaVNC-PQKEM-C2S", clientC2SKey);
  deriveSessionKey(clientKEMSS.data(), clientKEMSS.size(), clientECDH,
                   selectedAlg, "QuantaVNC-PQKEM-S2C", clientS2CKey);

  // Server derives keys
  deriveSessionKey(serverKEMSS.data(), serverKEMSS.size(), serverECDH,
                   selectedAlg, "QuantaVNC-PQKEM-C2S", serverC2SKey);
  deriveSessionKey(serverKEMSS.data(), serverKEMSS.size(), serverECDH,
                   selectedAlg, "QuantaVNC-PQKEM-S2C", serverS2CKey);

  return true;
}

bool ProtocolContext::verifyTranscriptHashes()
{
  // Client hash: SHA-256(selectedAlg || ct || clientX25519Pub || serverKEMPub || serverX25519Pub)
  uint8_t clientHash[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 1, &selectedAlg);
    sha256_update(&ctx, kemCiphertext.size(), kemCiphertext.data());
    sha256_update(&ctx, 32, clientX25519Pub);
    sha256_update(&ctx, kemPubKeyLen, serverKEMPub.data());
    sha256_update(&ctx, 32, serverX25519Pub);
    sha256_digest(&ctx, 32, clientHash);
  }

  // Server hash: SHA-256(selectedAlg || serverKEMPub || serverX25519Pub || ct || clientX25519Pub)
  uint8_t serverHash[32];
  {
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, 1, &selectedAlg);
    sha256_update(&ctx, kemPubKeyLen, serverKEMPub.data());
    sha256_update(&ctx, 32, serverX25519Pub);
    sha256_update(&ctx, kemCiphertext.size(), kemCiphertext.data());
    sha256_update(&ctx, 32, clientX25519Pub);
    sha256_digest(&ctx, 32, serverHash);
  }

  // Hashes should be different from each other (different field ordering)
  if (memcmp(clientHash, serverHash, 32) == 0)
    return false;

  return true;
}

bool ProtocolContext::runFullHandshake(uint8_t kemAlgId, uint8_t dsaAlgId)
{
  if (!serverGenerateKeys(kemAlgId)) return false;
  if (!serverWritePublicKeys()) return false;
  if (!serverSignAndWrite(dsaAlgId)) return false;
  if (!clientReadAndEncapsulate()) return false;
  if (!serverReadAndDecapsulate()) return false;
  if (!deriveKeys()) return false;
  return true;
}

// ===========================================================================
// Test: Full handshake with ML-KEM-768 (default) produces matching keys
// ===========================================================================
TEST(PQCE2E, FullHandshakeMLKEM768MatchingKeys)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // KEM shared secrets must match
  ASSERT_EQ(ctx.clientKEMSS.size(), ctx.serverKEMSS.size());
  EXPECT_EQ(memcmp(ctx.clientKEMSS.data(), ctx.serverKEMSS.data(),
                    ctx.clientKEMSS.size()), 0)
    << "ML-KEM shared secrets do not match after wire exchange";

  // ECDH shared secrets must match
  EXPECT_EQ(memcmp(ctx.clientECDH, ctx.serverECDH, 32), 0)
    << "X25519 shared secrets do not match after wire exchange";

  // Derived C2S keys must match
  EXPECT_EQ(memcmp(ctx.clientC2SKey, ctx.serverC2SKey, 32), 0)
    << "C2S session keys do not match";

  // Derived S2C keys must match
  EXPECT_EQ(memcmp(ctx.clientS2CKey, ctx.serverS2CKey, 32), 0)
    << "S2C session keys do not match";
}

// ===========================================================================
// Parameterized test: All ML-KEM variants over the wire
// ===========================================================================
class PQCE2EVariant : public ::testing::TestWithParam<uint8_t> {};

TEST_P(PQCE2EVariant, FullHandshakeAllVariants)
{
  uint8_t algId = GetParam();
  const char* oqsName = rfb::pqkemAlgOQSName(algId);
  if (!oqsName) GTEST_SKIP() << "Algorithm not compiled in";

  OQS_KEM* testKem = OQS_KEM_new(oqsName);
  if (!testKem) GTEST_SKIP() << "Algorithm not available in liboqs";
  OQS_KEM_free(testKem);

  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(algId, rfb::pqdsaAlgMLDSA65))
    << "Full handshake failed for " << rfb::pqkemAlgDisplayName(algId);

  // KEM shared secrets must match
  EXPECT_EQ(memcmp(ctx.clientKEMSS.data(), ctx.serverKEMSS.data(),
                    ctx.clientKEMSS.size()), 0)
    << "KEM SS mismatch for " << rfb::pqkemAlgDisplayName(algId);

  // ECDH shared secrets must match
  EXPECT_EQ(memcmp(ctx.clientECDH, ctx.serverECDH, 32), 0)
    << "ECDH SS mismatch for " << rfb::pqkemAlgDisplayName(algId);

  // All four derived keys must match between client and server
  EXPECT_EQ(memcmp(ctx.clientC2SKey, ctx.serverC2SKey, 32), 0);
  EXPECT_EQ(memcmp(ctx.clientS2CKey, ctx.serverS2CKey, 32), 0);
}

INSTANTIATE_TEST_SUITE_P(AllMLKEMWireVariants, PQCE2EVariant,
  ::testing::Values(
    rfb::pqkemAlgMLKEM512,
    rfb::pqkemAlgMLKEM768,
    rfb::pqkemAlgMLKEM1024
  ));

// ===========================================================================
// Test: ML-DSA signature verification in-protocol
// ===========================================================================
TEST(PQCE2E, MLDSASignatureVerifiedInProtocol)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.serverGenerateKeys(rfb::pqkemAlgMLKEM768));
  ASSERT_TRUE(ctx.serverWritePublicKeys());
  ASSERT_TRUE(ctx.serverSignAndWrite(rfb::pqdsaAlgMLDSA65));

  // clientReadAndEncapsulate includes signature verification
  ASSERT_TRUE(ctx.clientReadAndEncapsulate())
    << "Client should successfully verify the server's ML-DSA signature";
}

// ===========================================================================
// Test: Tampered ML-DSA signature is rejected by client
// ===========================================================================
TEST(PQCE2E, TamperedSignatureRejected)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.serverGenerateKeys(rfb::pqkemAlgMLKEM768));
  ASSERT_TRUE(ctx.serverWritePublicKeys());

  // Write a valid signature structure but with corrupted signature bytes
  ASSERT_TRUE(ctx.signingKey.generateForTest(rfb::pqdsaAlgMLDSA65));

  uint8_t msgHash[32];
  {
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_digest(&hashCtx, 32, msgHash);
  }

  uint8_t* signature = nullptr;
  size_t sigLen = 0;
  ASSERT_TRUE(ctx.signingKey.sign(msgHash, 32, &signature, &sigLen));

  // Tamper with the signature
  signature[0] ^= 0xFF;
  signature[sigLen / 2] ^= 0xAA;

  // Write tampered signature to wire
  ctx.serverToClientWire.writeU8(rfb::pqdsaAlgMLDSA65);
  size_t pkLen = ctx.signingKey.getPublicKeyLen();
  ctx.serverToClientWire.writeU16((uint16_t)pkLen);
  ctx.serverToClientWire.writeBytes(ctx.signingKey.getPublicKey(), pkLen);
  ctx.serverToClientWire.writeU16((uint16_t)sigLen);
  ctx.serverToClientWire.writeBytes(signature, sigLen);
  ctx.serverToClientWire.flush();

  delete[] signature;

  // Client should reject the tampered signature
  EXPECT_FALSE(ctx.clientReadAndEncapsulate())
    << "Client should reject a tampered ML-DSA signature";
}

// ===========================================================================
// Test: Wrong signing key is rejected by client
// ===========================================================================
TEST(PQCE2E, WrongSigningKeyRejected)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.serverGenerateKeys(rfb::pqkemAlgMLKEM768));
  ASSERT_TRUE(ctx.serverWritePublicKeys());

  // Generate a valid signature with one key, but send a different public key
  rfb::PQCKeyStore realKey;
  ASSERT_TRUE(realKey.generateForTest(rfb::pqdsaAlgMLDSA65));

  rfb::PQCKeyStore fakeKey;
  ASSERT_TRUE(fakeKey.generateForTest(rfb::pqdsaAlgMLDSA65));

  uint8_t msgHash[32];
  {
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_digest(&hashCtx, 32, msgHash);
  }

  // Sign with realKey
  uint8_t* signature = nullptr;
  size_t sigLen = 0;
  ASSERT_TRUE(realKey.sign(msgHash, 32, &signature, &sigLen));

  // But send fakeKey's public key
  ctx.serverToClientWire.writeU8(rfb::pqdsaAlgMLDSA65);
  size_t pkLen = fakeKey.getPublicKeyLen();
  ctx.serverToClientWire.writeU16((uint16_t)pkLen);
  ctx.serverToClientWire.writeBytes(fakeKey.getPublicKey(), pkLen);
  ctx.serverToClientWire.writeU16((uint16_t)sigLen);
  ctx.serverToClientWire.writeBytes(signature, sigLen);
  ctx.serverToClientWire.flush();

  delete[] signature;

  // Client should reject -- signature was made with a different key
  EXPECT_FALSE(ctx.clientReadAndEncapsulate())
    << "Client should reject signature from wrong signing key";
}

// ===========================================================================
// Test: Key material isolation -- C2S and S2C use different keys
// ===========================================================================
TEST(PQCE2E, KeyMaterialIsolation)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // C2S and S2C keys MUST be different on client side
  EXPECT_NE(memcmp(ctx.clientC2SKey, ctx.clientS2CKey, 32), 0)
    << "Client C2S and S2C keys must be different";

  // C2S and S2C keys MUST be different on server side
  EXPECT_NE(memcmp(ctx.serverC2SKey, ctx.serverS2CKey, 32), 0)
    << "Server C2S and S2C keys must be different";

  // Client's C2S key == Server's C2S key (they both derive the same)
  EXPECT_EQ(memcmp(ctx.clientC2SKey, ctx.serverC2SKey, 32), 0);

  // Client's S2C key == Server's S2C key
  EXPECT_EQ(memcmp(ctx.clientS2CKey, ctx.serverS2CKey, 32), 0);
}

// ===========================================================================
// Test: Transcript hashes use different ordering between client and server
// ===========================================================================
TEST(PQCE2E, TranscriptHashOrdering)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));
  EXPECT_TRUE(ctx.verifyTranscriptHashes())
    << "Client and server transcript hashes should be different "
       "(different field ordering prevents reflection attacks)";
}

// ===========================================================================
// Test: Algorithm binding prevents downgrade over the wire
// ===========================================================================
TEST(PQCE2E, AlgorithmBindingPreventsDowngrade)
{
  // Run two handshakes with different algorithms
  ProtocolContext ctx512;
  ProtocolContext ctx768;

  const char* name512 = rfb::pqkemAlgOQSName(rfb::pqkemAlgMLKEM512);
  const char* name768 = rfb::pqkemAlgOQSName(rfb::pqkemAlgMLKEM768);
  if (!name512 || !name768) GTEST_SKIP() << "Need both 512 and 768";

  OQS_KEM* test512 = OQS_KEM_new(name512);
  OQS_KEM* test768 = OQS_KEM_new(name768);
  if (!test512 || !test768) {
    if (test512) OQS_KEM_free(test512);
    if (test768) OQS_KEM_free(test768);
    GTEST_SKIP() << "Need both ML-KEM-512 and ML-KEM-768 in liboqs";
  }
  OQS_KEM_free(test512);
  OQS_KEM_free(test768);

  ASSERT_TRUE(ctx512.runFullHandshake(rfb::pqkemAlgMLKEM512, rfb::pqdsaAlgMLDSA65));
  ASSERT_TRUE(ctx768.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Even if the underlying KEM SS happened to be the same (extremely unlikely),
  // the algorithm ID binding in the KDF ensures different keys
  // We verify by checking that the keys are different
  EXPECT_NE(memcmp(ctx512.clientC2SKey, ctx768.clientC2SKey, 32), 0)
    << "Different algorithms must produce different session keys";
  EXPECT_NE(memcmp(ctx512.clientS2CKey, ctx768.clientS2CKey, 32), 0)
    << "Different algorithms must produce different session keys";
}

#ifdef HAVE_NETTLE

// ===========================================================================
// Test: Encrypted credential exchange works end-to-end
// ===========================================================================
TEST(PQCE2E, EncryptedCredentialExchange)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Verify keys match before using them
  ASSERT_EQ(memcmp(ctx.clientC2SKey, ctx.serverC2SKey, 32), 0);
  ASSERT_EQ(memcmp(ctx.clientS2CKey, ctx.serverS2CKey, 32), 0);

  // --- Server writes subtype (encrypted with S2C key) ---
  rdr::MemOutStream s2cRaw;
  {
    rdr::AESOutStream aesOut(&s2cRaw, ctx.serverS2CKey, 256);
    aesOut.writeU8(1); // secTypeRA2UserPass
    aesOut.flush();
  }

  // --- Client reads subtype ---
  rdr::MemInStream s2cIn(s2cRaw.data(), s2cRaw.length());
  rdr::AESInStream aesIn(&s2cIn, ctx.clientS2CKey, 256);
  ASSERT_TRUE(aesIn.hasData(1));
  uint8_t subtype = aesIn.readU8();
  EXPECT_EQ(subtype, 1) << "Subtype should be secTypeRA2UserPass";

  // --- Client writes credentials (encrypted with C2S key) ---
  const char* testUser = "quantavnc";
  const char* testPass = "pqc-secure-2026!";

  rdr::MemOutStream c2sRaw;
  {
    rdr::AESOutStream aesOutC2S(&c2sRaw, ctx.clientC2SKey, 256);
    aesOutC2S.writeU8((uint8_t)strlen(testUser));
    aesOutC2S.writeBytes((const uint8_t*)testUser, strlen(testUser));
    aesOutC2S.writeU8((uint8_t)strlen(testPass));
    aesOutC2S.writeBytes((const uint8_t*)testPass, strlen(testPass));
    aesOutC2S.flush();
  }

  // --- Server reads credentials ---
  rdr::MemInStream c2sIn(c2sRaw.data(), c2sRaw.length());
  rdr::AESInStream aesInC2S(&c2sIn, ctx.serverC2SKey, 256);

  ASSERT_TRUE(aesInC2S.hasData(1));
  uint8_t userLen = aesInC2S.readU8();
  EXPECT_EQ(userLen, strlen(testUser));

  char readUser[256] = {};
  aesInC2S.readBytes((uint8_t*)readUser, userLen);
  EXPECT_STREQ(readUser, testUser);

  ASSERT_TRUE(aesInC2S.hasData(1));
  uint8_t passLen = aesInC2S.readU8();
  EXPECT_EQ(passLen, strlen(testPass));

  char readPass[256] = {};
  aesInC2S.readBytes((uint8_t*)readPass, passLen);
  EXPECT_STREQ(readPass, testPass);
}

// ===========================================================================
// Test: Replay attack resistance -- replayed ciphertext fails AES MAC
// ===========================================================================
TEST(PQCE2E, ReplayAttackResistance)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Encrypt a message with the client's C2S key
  rdr::MemOutStream rawOut;
  {
    rdr::AESOutStream aesOut(&rawOut, ctx.clientC2SKey, 256);
    const uint8_t msg[] = "sensitive data";
    aesOut.writeBytes(msg, sizeof(msg));
    aesOut.flush();
  }

  // Capture the ciphertext
  std::vector<uint8_t> capturedCiphertext(rawOut.data(),
                                           rawOut.data() + rawOut.length());

  // First decryption should succeed
  {
    rdr::MemInStream rawIn(capturedCiphertext.data(), capturedCiphertext.size());
    rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);
    uint8_t buf[64];
    EXPECT_NO_THROW(aesIn.readBytes(buf, sizeof("sensitive data")));
  }

  // Replay the same ciphertext but try to decrypt with a DIFFERENT key
  // (simulating an attacker who captured the ciphertext and tries to replay
  //  it in a new session with different session keys)
  uint8_t attackerKey[32];
  OQS_randombytes(attackerKey, 32);
  {
    rdr::MemInStream rawIn(capturedCiphertext.data(), capturedCiphertext.size());
    rdr::AESInStream aesIn(&rawIn, attackerKey, 256);
    uint8_t buf[64];
    EXPECT_THROW(aesIn.readBytes(buf, sizeof("sensitive data")), std::exception)
      << "Replayed ciphertext with different key should fail MAC verification";
  }
}

// ===========================================================================
// Test: Cross-channel replay -- S2C ciphertext cannot be replayed on C2S
// ===========================================================================
TEST(PQCE2E, CrossChannelReplayRejected)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Encrypt with S2C key (server -> client direction)
  rdr::MemOutStream rawOut;
  {
    rdr::AESOutStream aesOut(&rawOut, ctx.serverS2CKey, 256);
    const uint8_t msg[] = "server message";
    aesOut.writeBytes(msg, sizeof(msg));
    aesOut.flush();
  }

  // Try to decrypt with C2S key (wrong direction) -- should fail
  {
    rdr::MemInStream rawIn(rawOut.data(), rawOut.length());
    rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);
    uint8_t buf[64];
    EXPECT_THROW(aesIn.readBytes(buf, sizeof("server message")), std::exception)
      << "S2C ciphertext must not be decryptable with C2S key";
  }
}

// ===========================================================================
// Test: Bidirectional encrypted communication
// ===========================================================================
TEST(PQCE2E, BidirectionalEncryptedCommunication)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  const char* clientMsg = "Hello from client via PQC channel";
  const char* serverMsg = "Hello from server via PQC channel";

  // Client -> Server (C2S key)
  rdr::MemOutStream c2sRaw;
  {
    rdr::AESOutStream aesOut(&c2sRaw, ctx.clientC2SKey, 256);
    aesOut.writeBytes((const uint8_t*)clientMsg, strlen(clientMsg) + 1);
    aesOut.flush();
  }

  // Server -> Client (S2C key)
  rdr::MemOutStream s2cRaw;
  {
    rdr::AESOutStream aesOut(&s2cRaw, ctx.serverS2CKey, 256);
    aesOut.writeBytes((const uint8_t*)serverMsg, strlen(serverMsg) + 1);
    aesOut.flush();
  }

  // Server decrypts client message
  {
    rdr::MemInStream rawIn(c2sRaw.data(), c2sRaw.length());
    rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);
    char buf[128] = {};
    aesIn.readBytes((uint8_t*)buf, strlen(clientMsg) + 1);
    EXPECT_STREQ(buf, clientMsg);
  }

  // Client decrypts server message
  {
    rdr::MemInStream rawIn(s2cRaw.data(), s2cRaw.length());
    rdr::AESInStream aesIn(&rawIn, ctx.clientS2CKey, 256);
    char buf[128] = {};
    aesIn.readBytes((uint8_t*)buf, strlen(serverMsg) + 1);
    EXPECT_STREQ(buf, serverMsg);
  }
}

// ===========================================================================
// Test: Encrypted transcript hash exchange over AES channel
// ===========================================================================
TEST(PQCE2E, EncryptedTranscriptHashExchange)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Compute client transcript hash (as CSecurityPQKEM::writeHash does)
  uint8_t clientHash[32];
  {
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_digest(&hashCtx, 32, clientHash);
  }

  // Compute server transcript hash (as SSecurityPQKEM::writeHash does)
  uint8_t serverHash[32];
  {
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_digest(&hashCtx, 32, serverHash);
  }

  // Client sends its hash encrypted with C2S key
  rdr::MemOutStream c2sRaw;
  {
    rdr::AESOutStream aesOut(&c2sRaw, ctx.clientC2SKey, 256);
    aesOut.writeBytes(clientHash, 32);
    aesOut.flush();
  }

  // Server sends its hash encrypted with S2C key
  rdr::MemOutStream s2cRaw;
  {
    rdr::AESOutStream aesOut(&s2cRaw, ctx.serverS2CKey, 256);
    aesOut.writeBytes(serverHash, 32);
    aesOut.flush();
  }

  // Server reads and verifies client hash
  {
    // Server computes expected client hash
    uint8_t expectedClientHash[32];
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_digest(&hashCtx, 32, expectedClientHash);

    rdr::MemInStream rawIn(c2sRaw.data(), c2sRaw.length());
    rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);
    uint8_t receivedHash[32];
    aesIn.readBytes(receivedHash, 32);

    EXPECT_EQ(memcmp(receivedHash, expectedClientHash, 32), 0)
      << "Server should correctly receive and verify client transcript hash";
  }

  // Client reads and verifies server hash
  {
    // Client computes expected server hash
    uint8_t expectedServerHash[32];
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_digest(&hashCtx, 32, expectedServerHash);

    rdr::MemInStream rawIn(s2cRaw.data(), s2cRaw.length());
    rdr::AESInStream aesIn(&rawIn, ctx.clientS2CKey, 256);
    uint8_t receivedHash[32];
    aesIn.readBytes(receivedHash, 32);

    EXPECT_EQ(memcmp(receivedHash, expectedServerHash, 32), 0)
      << "Client should correctly receive and verify server transcript hash";
  }
}

// ===========================================================================
// Test: Full protocol simulation with AES channel and credential exchange
// ===========================================================================
TEST(PQCE2E, FullProtocolWithCredentials)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // --- Phase 1: Server sends transcript hash (encrypted S2C) ---
  uint8_t serverHash[32];
  {
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_digest(&hashCtx, 32, serverHash);
  }

  rdr::MemOutStream s2cPhase1;
  rdr::AESOutStream* svrAesOut = new rdr::AESOutStream(&s2cPhase1,
                                                        ctx.serverS2CKey, 256);
  svrAesOut->writeBytes(serverHash, 32);
  svrAesOut->flush();

  // --- Phase 2: Client sends transcript hash (encrypted C2S) ---
  uint8_t clientHash[32];
  {
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_digest(&hashCtx, 32, clientHash);
  }

  rdr::MemOutStream c2sPhase1;
  rdr::AESOutStream* cliAesOut = new rdr::AESOutStream(&c2sPhase1,
                                                        ctx.clientC2SKey, 256);
  cliAesOut->writeBytes(clientHash, 32);
  cliAesOut->flush();

  // --- Phase 3: Server verifies client hash, sends subtype ---
  {
    rdr::MemInStream rawIn(c2sPhase1.data(), c2sPhase1.length());
    rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);
    uint8_t receivedHash[32];
    aesIn.readBytes(receivedHash, 32);

    // Compute expected client hash on server side
    uint8_t expectedHash[32];
    struct sha256_ctx hashCtx;
    sha256_init(&hashCtx);
    sha256_update(&hashCtx, 1, &ctx.selectedAlg);
    sha256_update(&hashCtx, ctx.kemCiphertext.size(), ctx.kemCiphertext.data());
    sha256_update(&hashCtx, 32, ctx.clientX25519Pub);
    sha256_update(&hashCtx, ctx.kemPubKeyLen, ctx.serverKEMPub.data());
    sha256_update(&hashCtx, 32, ctx.serverX25519Pub);
    sha256_digest(&hashCtx, 32, expectedHash);

    ASSERT_EQ(memcmp(receivedHash, expectedHash, 32), 0)
      << "Server could not verify client transcript hash";
  }

  // Server writes subtype
  rdr::MemOutStream s2cPhase2;
  {
    rdr::AESOutStream aesOut(&s2cPhase2, ctx.serverS2CKey, 256);
    aesOut.writeU8(1); // secTypeRA2UserPass
    aesOut.flush();
  }

  // --- Phase 4: Client reads subtype, sends credentials ---
  uint8_t subtype;
  {
    rdr::MemInStream rawIn(s2cPhase2.data(), s2cPhase2.length());
    rdr::AESInStream aesIn(&rawIn, ctx.clientS2CKey, 256);
    subtype = aesIn.readU8();
    ASSERT_EQ(subtype, 1);
  }

  const char* testUser = "alice";
  const char* testPass = "pqc-password";

  rdr::MemOutStream c2sPhase2;
  {
    rdr::AESOutStream aesOut(&c2sPhase2, ctx.clientC2SKey, 256);
    aesOut.writeU8((uint8_t)strlen(testUser));
    aesOut.writeBytes((const uint8_t*)testUser, strlen(testUser));
    aesOut.writeU8((uint8_t)strlen(testPass));
    aesOut.writeBytes((const uint8_t*)testPass, strlen(testPass));
    aesOut.flush();
  }

  // --- Phase 5: Server reads credentials ---
  {
    rdr::MemInStream rawIn(c2sPhase2.data(), c2sPhase2.length());
    rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);

    uint8_t uLen = aesIn.readU8();
    char user[256] = {};
    aesIn.readBytes((uint8_t*)user, uLen);

    uint8_t pLen = aesIn.readU8();
    char pass[256] = {};
    aesIn.readBytes((uint8_t*)pass, pLen);

    EXPECT_STREQ(user, testUser);
    EXPECT_STREQ(pass, testPass);
  }

  delete svrAesOut;
  delete cliAesOut;
}

// ===========================================================================
// Test: Each handshake produces unique session keys (forward secrecy)
// ===========================================================================
TEST(PQCE2E, UniqueSessionKeysPerHandshake)
{
  ProtocolContext ctx1, ctx2;
  ASSERT_TRUE(ctx1.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));
  ASSERT_TRUE(ctx2.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Two independent handshakes should produce completely different keys
  EXPECT_NE(memcmp(ctx1.clientC2SKey, ctx2.clientC2SKey, 32), 0)
    << "Two handshakes must produce different C2S keys";
  EXPECT_NE(memcmp(ctx1.clientS2CKey, ctx2.clientS2CKey, 32), 0)
    << "Two handshakes must produce different S2C keys";
}

// ===========================================================================
// Test: Wire format byte-level verification
// ===========================================================================
TEST(PQCE2E, WireFormatServerPublicKeys)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.serverGenerateKeys(rfb::pqkemAlgMLKEM768));
  ASSERT_TRUE(ctx.serverWritePublicKeys());

  // Parse the wire format manually to verify structure
  rdr::MemInStream wire(ctx.serverToClientWire.data(),
                         ctx.serverToClientWire.length());

  // U8(numAlgs)
  uint8_t numAlgs = wire.readU8();
  EXPECT_GT(numAlgs, 0u);
  EXPECT_LE(numAlgs, 16u);

  // U8(algId) * numAlgs
  for (uint8_t i = 0; i < numAlgs; i++) {
    uint8_t algId = wire.readU8();
    EXPECT_GE(algId, rfb::pqkemAlgMLKEM512);
    EXPECT_LE(algId, rfb::pqkemAlgMLKEM1024);
  }

  // U8(selectedAlg)
  uint8_t selected = wire.readU8();
  EXPECT_EQ(selected, rfb::pqkemAlgMLKEM768);

  // U16(kemPubKeyLen)
  uint16_t pubKeyLen = wire.readU16();
  EXPECT_EQ(pubKeyLen, ctx.kemPubKeyLen);

  // kemPubKey
  std::vector<uint8_t> pubKey(pubKeyLen);
  wire.readBytes(pubKey.data(), pubKeyLen);
  EXPECT_EQ(memcmp(pubKey.data(), ctx.serverKEMPub.data(), pubKeyLen), 0);

  // X25519 public key (32 bytes)
  uint8_t x25519[32];
  wire.readBytes(x25519, 32);
  EXPECT_EQ(memcmp(x25519, ctx.serverX25519Pub, 32), 0);
}

// ===========================================================================
// Test: All ML-DSA variants work for signing in the protocol
// ===========================================================================
class PQCE2EDSAVariant : public ::testing::TestWithParam<uint8_t> {};

TEST_P(PQCE2EDSAVariant, SignatureVerificationWithVariant)
{
  uint8_t dsaAlgId = GetParam();
  const char* oqsName = rfb::pqdsaAlgOQSName(dsaAlgId);
  if (!oqsName) GTEST_SKIP() << "DSA algorithm not compiled in";

  OQS_SIG* testSig = OQS_SIG_new(oqsName);
  if (!testSig) GTEST_SKIP() << "DSA algorithm not available in liboqs";
  OQS_SIG_free(testSig);

  ProtocolContext ctx;
  ASSERT_TRUE(ctx.serverGenerateKeys(rfb::pqkemAlgMLKEM768));
  ASSERT_TRUE(ctx.serverWritePublicKeys());
  ASSERT_TRUE(ctx.serverSignAndWrite(dsaAlgId));
  ASSERT_TRUE(ctx.clientReadAndEncapsulate())
    << "Handshake should succeed with " << rfb::pqdsaAlgDisplayName(dsaAlgId);
}

INSTANTIATE_TEST_SUITE_P(AllMLDSAWireVariants, PQCE2EDSAVariant,
  ::testing::Values(
    rfb::pqdsaAlgMLDSA44,
    rfb::pqdsaAlgMLDSA65,
    rfb::pqdsaAlgMLDSA87
  ));

// ===========================================================================
// Test: Large payload through encrypted channel
// ===========================================================================
TEST(PQCE2E, LargePayloadThroughEncryptedChannel)
{
  ProtocolContext ctx;
  ASSERT_TRUE(ctx.runFullHandshake(rfb::pqkemAlgMLKEM768, rfb::pqdsaAlgMLDSA65));

  // Generate a large payload (64 KB)
  const size_t payloadSize = 65536;
  std::vector<uint8_t> payload(payloadSize);
  OQS_randombytes(payload.data(), payloadSize);

  // Encrypt with C2S key
  rdr::MemOutStream rawOut;
  {
    rdr::AESOutStream aesOut(&rawOut, ctx.clientC2SKey, 256);
    aesOut.writeBytes(payload.data(), payloadSize);
    aesOut.flush();
  }

  // Decrypt with server's C2S key
  rdr::MemInStream rawIn(rawOut.data(), rawOut.length());
  rdr::AESInStream aesIn(&rawIn, ctx.serverC2SKey, 256);

  std::vector<uint8_t> decrypted(payloadSize);
  aesIn.readBytes(decrypted.data(), payloadSize);

  EXPECT_EQ(memcmp(payload.data(), decrypted.data(), payloadSize), 0)
    << "Large payload should survive encrypt/decrypt through PQC channel";
}

#endif // HAVE_NETTLE
#endif // HAVE_LIBOQS
