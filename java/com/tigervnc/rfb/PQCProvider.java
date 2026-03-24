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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

package com.tigervnc.rfb;

/**
 * Abstraction for post-quantum cryptographic operations.
 * Implementations may use Bouncy Castle (pure Java) or liboqs (JNI).
 */
public interface PQCProvider {

  /** KEM encapsulation result */
  public static class KEMEncapsResult {
    public final byte[] ciphertext;
    public final byte[] sharedSecret;
    public KEMEncapsResult(byte[] ciphertext, byte[] sharedSecret) {
      this.ciphertext = ciphertext;
      this.sharedSecret = sharedSecret;
    }
  }

  /**
   * Encapsulate against a ML-KEM public key.
   * @param algId algorithm ID (1=ML-KEM-512, 2=ML-KEM-768, 3=ML-KEM-1024)
   * @param publicKey the server's KEM public key
   * @return ciphertext + shared secret
   */
  KEMEncapsResult kemEncapsulate(int algId, byte[] publicKey);

  /**
   * Verify an ML-DSA signature.
   * @param algId algorithm ID (1=ML-DSA-44, 2=ML-DSA-65, 3=ML-DSA-87)
   * @param publicKey the signer's public key
   * @param message the message that was signed
   * @param signature the signature to verify
   * @return true if valid
   */
  boolean dsaVerify(int algId, byte[] publicKey, byte[] message, byte[] signature);

  /**
   * Perform X25519 scalar multiplication: result = scalar * point
   */
  byte[] x25519Multiply(byte[] scalar, byte[] point);

  /**
   * Get the provider name for logging.
   */
  String getName();

  /**
   * Check if a KEM algorithm ID is supported.
   */
  boolean isKEMSupported(int algId);
}
