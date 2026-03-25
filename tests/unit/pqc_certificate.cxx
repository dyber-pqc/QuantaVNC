/* Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string>

#include <gtest/gtest.h>

#ifdef HAVE_GNUTLS
#include <rfb/PQCCertificate.h>
#include <gnutls/gnutls.h>
#endif

// -----------------------------------------------------------------------
// getPQPriorityString tests
// -----------------------------------------------------------------------

#ifdef HAVE_GNUTLS

TEST(PQCCertificate, PriorityStringIsNonEmpty)
{
  std::string prio = rfb::PQCCertificate::getPQPriorityString();
  EXPECT_FALSE(prio.empty());
}

TEST(PQCCertificate, PriorityStringStartsWithNORMAL)
{
  std::string prio = rfb::PQCCertificate::getPQPriorityString();
  EXPECT_EQ(prio.substr(0, 6), "NORMAL");
}

TEST(PQCCertificate, PriorityStringIsValidForGnuTLS)
{
  // The string returned must be accepted by gnutls_priority_init().
  std::string prio = rfb::PQCCertificate::getPQPriorityString();

  gnutls_priority_t pcache = nullptr;
  const char* errpos = nullptr;
  int ret = gnutls_priority_init(&pcache, prio.c_str(), &errpos);
  EXPECT_EQ(ret, GNUTLS_E_SUCCESS)
      << "Priority string rejected at: "
      << (errpos ? errpos : "(null)");
  if (pcache)
    gnutls_priority_deinit(pcache);
}

TEST(PQCCertificate, AnonPriorityStringContainsAnon)
{
  std::string prio = rfb::PQCCertificate::getPQAnonPriorityString();
  EXPECT_NE(prio.find("ANON"), std::string::npos);
}

TEST(PQCCertificate, AnonPriorityStringIsValidForGnuTLS)
{
  std::string prio = rfb::PQCCertificate::getPQAnonPriorityString();

  gnutls_priority_t pcache = nullptr;
  const char* errpos = nullptr;
  int ret = gnutls_priority_init(&pcache, prio.c_str(), &errpos);
  EXPECT_EQ(ret, GNUTLS_E_SUCCESS)
      << "Anon priority string rejected at: "
      << (errpos ? errpos : "(null)");
  if (pcache)
    gnutls_priority_deinit(pcache);
}

// -----------------------------------------------------------------------
// PQ group availability detection
// -----------------------------------------------------------------------

TEST(PQCCertificate, PQGroupAvailabilityDoesNotCrash)
{
  // This must never throw or crash regardless of GnuTLS version.
  bool available = rfb::PQCCertificate::isPQGroupAvailable();
  // We cannot assert the value since it depends on the linked
  // GnuTLS, but we can verify the call completes.
  (void)available;
}

TEST(PQCCertificate, PQGroupConsistentWithPriorityString)
{
  bool available = rfb::PQCCertificate::isPQGroupAvailable();
  std::string prio = rfb::PQCCertificate::getPQPriorityString();

  if (available) {
    // When PQ groups are available the priority string must
    // reference the PQ group.
    EXPECT_NE(prio.find("X25519MLKEM768"), std::string::npos)
        << "PQ group available but priority string does not reference it";
  } else {
    // When not available, the string should be plain NORMAL.
    EXPECT_EQ(prio, "NORMAL")
        << "PQ group not available but priority string is not plain NORMAL";
  }
}

// -----------------------------------------------------------------------
// Graceful degradation
// -----------------------------------------------------------------------

TEST(PQCCertificate, GracefulDegradationPriorityString)
{
  // Even if PQ is not available, getPQPriorityString must return a
  // usable string (at minimum "NORMAL").
  std::string prio = rfb::PQCCertificate::getPQPriorityString();
  EXPECT_GE(prio.size(), strlen("NORMAL"));

  // Validate it with GnuTLS
  gnutls_priority_t pcache = nullptr;
  const char* errpos = nullptr;
  int ret = gnutls_priority_init(&pcache, prio.c_str(), &errpos);
  EXPECT_EQ(ret, GNUTLS_E_SUCCESS);
  if (pcache)
    gnutls_priority_deinit(pcache);
}

TEST(PQCCertificate, SupportInfoDoesNotCrash)
{
  std::string info = rfb::PQCCertificate::getPQSupportInfo();
  EXPECT_FALSE(info.empty());
  // Must contain the GnuTLS version line
  EXPECT_NE(info.find("GnuTLS version:"), std::string::npos);
}

TEST(PQCCertificate, VerifyEmptyChainFails)
{
  std::string errorOut;
  bool ok = rfb::PQCCertificate::verifyCertificateChain(nullptr, 0,
                                                          nullptr, errorOut);
  EXPECT_FALSE(ok);
  EXPECT_FALSE(errorOut.empty());
}

TEST(PQCCertificate, GenerateSelfSignedDoesNotCrash)
{
  std::string cert, key, err;
  bool ok = rfb::PQCCertificate::generateSelfSignedCert(cert, key, err);
  // We expect success on any system with GnuTLS, since we fall
  // back to ECDSA when ML-DSA is unavailable.
  EXPECT_TRUE(ok) << "generateSelfSignedCert failed: " << err;
  if (ok) {
    EXPECT_NE(cert.find("BEGIN CERTIFICATE"), std::string::npos);
    EXPECT_NE(key.find("BEGIN"), std::string::npos);
  }
}

#else  // !HAVE_GNUTLS

TEST(PQCCertificate, SkippedWithoutGnuTLS)
{
  GTEST_SKIP() << "GnuTLS not available, PQCCertificate tests skipped";
}

#endif  // HAVE_GNUTLS
