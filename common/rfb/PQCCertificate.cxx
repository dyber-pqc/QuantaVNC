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

#ifndef HAVE_GNUTLS
#error "This source should not be compiled without HAVE_GNUTLS defined"
#endif

#include <cstring>
#include <ctime>

#include <core/LogWriter.h>

#include <rfb/PQCCertificate.h>

#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

using namespace rfb;

static core::LogWriter vlog("PQCCert");

// ---------------------------------------------------------------------------
// Runtime PQ group detection
// ---------------------------------------------------------------------------

bool PQCCertificate::isPQGroupAvailable()
{
  // gnutls_group_get_id() returns GNUTLS_GROUP_INVALID (0) when the
  // name is not recognised by the linked library.  We probe for the
  // hybrid X25519+ML-KEM-768 group that GnuTLS >= 3.8.8 exposes.
  // The name used by GnuTLS is "X25519MLKEM768" (without hyphens).
  gnutls_group_t grp = gnutls_group_get_id("X25519MLKEM768");
  if (grp != 0) {
    vlog.debug("PQ group X25519MLKEM768 detected (id=%d)", (int)grp);
    return true;
  }

  // Also try the hyphenated variant some builds may use.
  grp = gnutls_group_get_id("X25519-MLKEM768");
  if (grp != 0) {
    vlog.debug("PQ group X25519-MLKEM768 detected (id=%d)", (int)grp);
    return true;
  }

  vlog.debug("No PQ hybrid key-exchange group found in GnuTLS");
  return false;
}

// ---------------------------------------------------------------------------
// Priority strings
// ---------------------------------------------------------------------------

std::string PQCCertificate::getPQPriorityString()
{
  if (isPQGroupAvailable()) {
    // Prefer the PQ hybrid group, then fall back to classical curves.
    // The "-GROUP-ALL" removes the default group list so we control
    // the exact preference order.
    return "NORMAL:-GROUP-ALL:+GROUP-X25519MLKEM768"
           ":+GROUP-X25519:+GROUP-SECP256R1";
  }

  // PQ not available -- return a safe classical-only string.
  return "NORMAL";
}

std::string PQCCertificate::getPQAnonPriorityString()
{
  std::string prio = getPQPriorityString();
  prio += ":+ANON-ECDH:+ANON-DH";
  return prio;
}

// ---------------------------------------------------------------------------
// Self-signed certificate generation
// ---------------------------------------------------------------------------

// Helper: detect whether GnuTLS knows the MLDSA65 algorithm at runtime
// by trying gnutls_pk_get_id().  This avoids compile-time guards.
static bool isMldsaAvailable()
{
  // gnutls_pk_get_id() returns GNUTLS_PK_UNKNOWN when the name is
  // not recognised.
  gnutls_pk_algorithm_t pk = gnutls_pk_get_id("MLDSA65");
  return pk != GNUTLS_PK_UNKNOWN;
}

bool PQCCertificate::generateSelfSignedCert(std::string& certPEM,
                                             std::string& keyPEM,
                                             std::string& errorOut)
{
  gnutls_x509_privkey_t key = nullptr;
  gnutls_x509_crt_t crt = nullptr;
  int ret;
  bool usePQ = isMldsaAvailable();

  certPEM.clear();
  keyPEM.clear();
  errorOut.clear();

  // --- Generate private key ---
  ret = gnutls_x509_privkey_init(&key);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("privkey_init: ") + gnutls_strerror(ret);
    return false;
  }

  if (usePQ) {
    // ML-DSA-65 (Dilithium3-equivalent post-quantum signature)
    gnutls_pk_algorithm_t mldsa = gnutls_pk_get_id("MLDSA65");
    ret = gnutls_x509_privkey_generate(key, mldsa, 0, 0);
    if (ret != GNUTLS_E_SUCCESS) {
      // Fall back to classical if generation fails at runtime
      vlog.info("ML-DSA-65 key generation failed (%s), falling back to ECDSA",
                gnutls_strerror(ret));
      usePQ = false;
    }
  }

  if (!usePQ) {
    ret = gnutls_x509_privkey_generate(key, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0);
    if (ret != GNUTLS_E_SUCCESS) {
      errorOut = std::string("privkey_generate ECDSA: ") + gnutls_strerror(ret);
      gnutls_x509_privkey_deinit(key);
      return false;
    }
  }

  // --- Create self-signed certificate ---
  ret = gnutls_x509_crt_init(&crt);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("crt_init: ") + gnutls_strerror(ret);
    gnutls_x509_privkey_deinit(key);
    return false;
  }

  gnutls_x509_crt_set_version(crt, 3);

  unsigned char serial[16];
  gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial));
  gnutls_x509_crt_set_serial(crt, serial, sizeof(serial));

  gnutls_x509_crt_set_activation_time(crt, time(nullptr));
  // Valid for 1 year
  gnutls_x509_crt_set_expiration_time(crt, time(nullptr) + 365 * 24 * 60 * 60);

  const char* dn = "CN=QuantaVNC Self-Signed,O=QuantaVNC";
  ret = gnutls_x509_crt_set_dn(crt, dn, nullptr);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("set_dn: ") + gnutls_strerror(ret);
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(key);
    return false;
  }

  ret = gnutls_x509_crt_set_key(crt, key);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("set_key: ") + gnutls_strerror(ret);
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(key);
    return false;
  }

  // Self-sign with the same key
  gnutls_digest_algorithm_t dig = usePQ ? GNUTLS_DIG_SHA512 : GNUTLS_DIG_SHA256;
  ret = gnutls_x509_crt_sign2(crt, crt, key, dig, 0);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("crt_sign2: ") + gnutls_strerror(ret);
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(key);
    return false;
  }

  // --- Export to PEM ---
  gnutls_datum_t certDatum = {nullptr, 0};
  gnutls_datum_t keyDatum = {nullptr, 0};

  ret = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &certDatum);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("crt_export2: ") + gnutls_strerror(ret);
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(key);
    return false;
  }

  ret = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &keyDatum);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("privkey_export2: ") + gnutls_strerror(ret);
    gnutls_free(certDatum.data);
    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(key);
    return false;
  }

  certPEM.assign(reinterpret_cast<char*>(certDatum.data), certDatum.size);
  keyPEM.assign(reinterpret_cast<char*>(keyDatum.data), keyDatum.size);

  gnutls_free(certDatum.data);
  gnutls_free(keyDatum.data);
  gnutls_x509_crt_deinit(crt);
  gnutls_x509_privkey_deinit(key);

  vlog.info("Generated self-signed certificate (algorithm: %s)",
            usePQ ? "ML-DSA-65" : "ECDSA-P256");

  return true;
}

// ---------------------------------------------------------------------------
// Certificate chain verification
// ---------------------------------------------------------------------------

bool PQCCertificate::verifyCertificateChain(const gnutls_datum_t* certData,
                                             unsigned int certCount,
                                             const char* caFile,
                                             std::string& errorOut)
{
  errorOut.clear();

  if (certData == nullptr || certCount == 0) {
    errorOut = "Empty certificate chain";
    return false;
  }

  gnutls_x509_trust_list_t tl = nullptr;
  int ret;

  ret = gnutls_x509_trust_list_init(&tl, 0);
  if (ret != GNUTLS_E_SUCCESS) {
    errorOut = std::string("trust_list_init: ") + gnutls_strerror(ret);
    return false;
  }

  // Load system trust store
  ret = gnutls_x509_trust_list_add_system_trust(tl, 0, 0);
  if (ret < 0) {
    vlog.debug("Could not load system trust store: %s", gnutls_strerror(ret));
  }

  // Load user-specified CA file if provided
  if (caFile != nullptr && caFile[0] != '\0') {
    ret = gnutls_x509_trust_list_add_trust_file(tl, caFile, nullptr,
                                                 GNUTLS_X509_FMT_PEM, 0, 0);
    if (ret < 0) {
      vlog.debug("Could not load CA file '%s': %s", caFile, gnutls_strerror(ret));
    }
  }

  // Import the certificate chain
  gnutls_x509_crt_t* certs = new gnutls_x509_crt_t[certCount];
  for (unsigned int i = 0; i < certCount; i++) {
    gnutls_x509_crt_init(&certs[i]);
    ret = gnutls_x509_crt_import(certs[i], &certData[i], GNUTLS_X509_FMT_DER);
    if (ret != GNUTLS_E_SUCCESS) {
      errorOut = std::string("crt_import: ") + gnutls_strerror(ret);
      for (unsigned int j = 0; j <= i; j++)
        gnutls_x509_crt_deinit(certs[j]);
      delete[] certs;
      gnutls_x509_trust_list_deinit(tl, 0);
      return false;
    }
  }

  unsigned int verifyStatus = 0;
  ret = gnutls_x509_trust_list_verify_crt(tl, certs, certCount,
                                           0, &verifyStatus, nullptr);

  bool valid = (ret == GNUTLS_E_SUCCESS && verifyStatus == 0);

  if (!valid) {
    if (ret != GNUTLS_E_SUCCESS) {
      errorOut = std::string("verify_crt: ") + gnutls_strerror(ret);
    } else {
      gnutls_datum_t statusStr;
      ret = gnutls_certificate_verification_status_print(verifyStatus,
                                                          GNUTLS_CRT_X509,
                                                          &statusStr, 0);
      if (ret == GNUTLS_E_SUCCESS) {
        errorOut = reinterpret_cast<char*>(statusStr.data);
        gnutls_free(statusStr.data);
      } else {
        errorOut = "Certificate verification failed with unknown status";
      }
    }
  }

  for (unsigned int i = 0; i < certCount; i++)
    gnutls_x509_crt_deinit(certs[i]);
  delete[] certs;
  gnutls_x509_trust_list_deinit(tl, 0);

  return valid;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

std::string PQCCertificate::getPQSupportInfo()
{
  std::string info;

  info += "GnuTLS version: ";
  info += gnutls_check_version(nullptr);

  info += "\nPQ hybrid group (X25519MLKEM768): ";
  info += isPQGroupAvailable() ? "available" : "not available";

  info += "\nML-DSA-65 signatures: ";
  info += isMldsaAvailable() ? "available" : "not available";

  return info;
}
