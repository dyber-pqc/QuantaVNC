/* Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

package com.tigervnc.rfb;

import java.lang.reflect.*;
import java.security.SecureRandom;

/**
 * liboqs-java PQC provider using reflection for zero compile-time dependency.
 * Requires liboqs-java.jar + native liboqs on the library path at runtime.
 * Uses the same native crypto as the QuantaVNC C++ client for maximum
 * compatibility.
 */
public class LiboqsPQCProvider implements PQCProvider {

  public static boolean isAvailable() {
    try {
      Class.forName("org.openquantumsafe.KEMs");
      // Try to actually create a KEM to verify native lib loads
      Class<?> kemClass = Class.forName("org.openquantumsafe.KEM");
      Object kem = kemClass.getConstructor(String.class).newInstance("ML-KEM-768");
      kemClass.getMethod("dispose").invoke(kem);
      return true;
    } catch (java.lang.Exception e) {
      return false;
    } catch (UnsatisfiedLinkError e) {
      return false;
    }
  }

  private static String kemOqsName(int algId) {
    switch (algId) {
      case 1: return "ML-KEM-512";
      case 2: return "ML-KEM-768";
      case 3: return "ML-KEM-1024";
      default: return null;
    }
  }

  private static String dsaOqsName(int algId) {
    switch (algId) {
      case 1: return "ML-DSA-44";
      case 2: return "ML-DSA-65";
      case 3: return "ML-DSA-87";
      default: return null;
    }
  }

  public KEMEncapsResult kemEncapsulate(int algId, byte[] publicKey) {
    Object kem = null;
    try {
      String name = kemOqsName(algId);
      if (name == null)
        throw new IllegalArgumentException("Unknown KEM algorithm: " + algId);

      Class<?> kemClass = Class.forName("org.openquantumsafe.KEM");
      kem = kemClass.getConstructor(String.class).newInstance(name);

      // Pair<byte[], byte[]> encaps_secret = kem.encaps(publicKey);
      // Returns Pair where getLeft()=ciphertext, getRight()=sharedSecret
      Method encaps = kemClass.getMethod("encaps", byte[].class);
      Object pair = encaps.invoke(kem, (Object) publicKey);

      Method getLeft = pair.getClass().getMethod("getLeft");
      Method getRight = pair.getClass().getMethod("getRight");

      byte[] ciphertext = (byte[]) getLeft.invoke(pair);
      byte[] sharedSecret = (byte[]) getRight.invoke(pair);

      return new KEMEncapsResult(ciphertext, sharedSecret);
    } catch (java.lang.Exception e) {
      throw new RuntimeException("liboqs ML-KEM encapsulation failed: " + e.getMessage(), e);
    } finally {
      if (kem != null) {
        try {
          kem.getClass().getMethod("dispose").invoke(kem);
        } catch (java.lang.Exception e) { /* ignore */ }
      }
    }
  }

  public boolean dsaVerify(int algId, byte[] publicKey, byte[] message, byte[] signature) {
    Object sig = null;
    try {
      String name = dsaOqsName(algId);
      if (name == null) return false;

      Class<?> sigClass = Class.forName("org.openquantumsafe.Signature");
      sig = sigClass.getConstructor(String.class).newInstance(name);

      Method verify = sigClass.getMethod("verify", byte[].class, byte[].class, byte[].class);
      return (Boolean) verify.invoke(sig, message, signature, publicKey);
    } catch (java.lang.Exception e) {
      throw new RuntimeException("liboqs ML-DSA verify failed: " + e.getMessage(), e);
    } finally {
      if (sig != null) {
        try {
          sig.getClass().getMethod("dispose").invoke(sig);
        } catch (java.lang.Exception e) { /* ignore */ }
      }
    }
  }

  public byte[] x25519Multiply(byte[] scalar, byte[] point) {
    // liboqs doesn't provide X25519 directly.
    // Delegate to the built-in X25519 implementation.
    return X25519.scalarMult(scalar, point);
  }

  public String getName() { return "liboqs-java (native)"; }

  public boolean isKEMSupported(int algId) {
    return kemOqsName(algId) != null;
  }
}
