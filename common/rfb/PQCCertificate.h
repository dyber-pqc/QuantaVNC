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

#ifndef __PQC_CERTIFICATE_H__
#define __PQC_CERTIFICATE_H__

#ifndef HAVE_GNUTLS
#error "This header should not be compiled without HAVE_GNUTLS defined"
#endif

#include <string>

#include <gnutls/gnutls.h>

namespace rfb {

  // Utility class for post-quantum certificate and TLS group operations.
  // All methods use runtime detection of GnuTLS PQ capabilities and
  // gracefully degrade when PQ support is not available.
  class PQCCertificate {
  public:

    // Check whether the linked GnuTLS library recognises the
    // X25519MLKEM768 hybrid key-exchange group at runtime.
    // Returns true if the group ID is known (non-zero).
    static bool isPQGroupAvailable();

    // Return a GnuTLS priority string that prefers the PQ hybrid
    // group when available, falling back to classical groups.
    // The returned string is always a valid NORMAL-based priority.
    static std::string getPQPriorityString();

    // Return a GnuTLS priority string suitable for anonymous TLS
    // sessions that prefers PQ groups when available.
    static std::string getPQAnonPriorityString();

    // Generate a self-signed X.509 certificate.  When the linked
    // GnuTLS supports ML-DSA-65 (MLDSA65) the certificate will use
    // that algorithm; otherwise it falls back to ECDSA/SECP256R1.
    // On success the PEM-encoded certificate and private key are
    // written to `certPEM` and `keyPEM` respectively and the method
    // returns true.  On failure it returns false and `errorOut`
    // contains a human-readable description.
    static bool generateSelfSignedCert(std::string& certPEM,
                                       std::string& keyPEM,
                                       std::string& errorOut);

    // Verify a PQ-aware certificate chain stored in `certData`
    // (DER-encoded, as obtained from gnutls_certificate_get_peers).
    // `caFile` is the path to a PEM trust store (may be empty to
    // use the system store).  Returns true when the chain is valid.
    // On failure, `errorOut` contains a description.
    static bool verifyCertificateChain(const gnutls_datum_t* certData,
                                       unsigned int certCount,
                                       const char* caFile,
                                       std::string& errorOut);

    // Return a human-readable description of the PQ support status
    // of the linked GnuTLS library (useful for diagnostics).
    static std::string getPQSupportInfo();

  private:
    PQCCertificate();  // static-only class
  };

}

#endif
