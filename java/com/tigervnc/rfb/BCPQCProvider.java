/* Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

package com.tigervnc.rfb;

import java.lang.reflect.*;
import java.security.*;

/**
 * Bouncy Castle PQC provider using reflection for zero compile-time dependency.
 * Requires bcprov-jdk18on.jar + bcpqc-jdk18on.jar on the classpath at runtime.
 */
public class BCPQCProvider implements PQCProvider {

  static {
    try {
      Class<?> bcProv = Class.forName(
        "org.bouncycastle.jce.provider.BouncyCastleProvider");
      if (Security.getProvider("BC") == null)
        Security.addProvider((Provider) bcProv.getDeclaredConstructor().newInstance());
    } catch (Exception e) { /* not available */ }

    try {
      Class<?> pqcProv = Class.forName(
        "org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider");
      if (Security.getProvider("BCPQC") == null)
        Security.addProvider((Provider) pqcProv.getDeclaredConstructor().newInstance());
    } catch (Exception e) { /* not available */ }
  }

  public static boolean isAvailable() {
    try {
      Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters");
      Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters");
      Class.forName("org.bouncycastle.math.ec.rfc7748.X25519");
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }

  private static String kemParamField(int algId) {
    switch (algId) {
      case 1: return "ml_kem_512";
      case 2: return "ml_kem_768";
      case 3: return "ml_kem_1024";
      default: return null;
    }
  }

  private static String dsaParamField(int algId) {
    switch (algId) {
      case 1: return "ml_dsa_44";
      case 2: return "ml_dsa_65";
      case 3: return "ml_dsa_87";
      default: return null;
    }
  }

  public KEMEncapsResult kemEncapsulate(int algId, byte[] publicKey) {
    try {
      String field = kemParamField(algId);
      if (field == null)
        throw new IllegalArgumentException("Unknown KEM algorithm: " + algId);

      Class<?> paramsClass = Class.forName(
        "org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters");
      Object params = paramsClass.getField(field).get(null);

      Class<?> pubKeyClass = Class.forName(
        "org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters");
      Object pubKeyParams = pubKeyClass.getConstructor(paramsClass, byte[].class)
        .newInstance(params, publicKey);

      Class<?> generatorClass = Class.forName(
        "org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator");
      Object generator = generatorClass.getConstructor(SecureRandom.class)
        .newInstance(new SecureRandom());

      // AsymmetricKeyParameter is the base class
      Class<?> asymKeyParam = Class.forName(
        "org.bouncycastle.crypto.params.AsymmetricKeyParameter");
      Method genEncaps = generatorClass.getMethod("generateEncapsulated", asymKeyParam);
      Object result = genEncaps.invoke(generator, pubKeyParams);

      byte[] ciphertext = (byte[]) result.getClass().getMethod("getEncapsulation")
        .invoke(result);
      byte[] sharedSecret = (byte[]) result.getClass().getMethod("getSecret")
        .invoke(result);

      return new KEMEncapsResult(ciphertext, sharedSecret);
    } catch (Exception e) {
      throw new RuntimeException("BC ML-KEM encapsulation failed: " + e.getMessage(), e);
    }
  }

  public boolean dsaVerify(int algId, byte[] publicKey, byte[] message, byte[] signature) {
    try {
      String field = dsaParamField(algId);
      if (field == null) return false;

      Class<?> paramsClass = Class.forName(
        "org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters");
      Object params = paramsClass.getField(field).get(null);

      Class<?> pubKeyClass = Class.forName(
        "org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters");
      Object pubKeyParams = pubKeyClass.getConstructor(paramsClass, byte[].class)
        .newInstance(params, publicKey);

      Class<?> signerClass = Class.forName(
        "org.bouncycastle.pqc.crypto.mldsa.MLDSASigner");
      Object signer = signerClass.getDeclaredConstructor().newInstance();

      Class<?> cipherParams = Class.forName(
        "org.bouncycastle.crypto.CipherParameters");
      signerClass.getMethod("init", boolean.class, cipherParams)
        .invoke(signer, false, pubKeyParams);

      return (Boolean) signerClass.getMethod("verifySignature", byte[].class, byte[].class)
        .invoke(signer, message, signature);
    } catch (Exception e) {
      throw new RuntimeException("BC ML-DSA verify failed: " + e.getMessage(), e);
    }
  }

  public byte[] x25519Multiply(byte[] scalar, byte[] point) {
    try {
      Class<?> x25519 = Class.forName("org.bouncycastle.math.ec.rfc7748.X25519");
      byte[] result = new byte[32];
      x25519.getMethod("scalarMult", byte[].class, int.class,
                        byte[].class, int.class, byte[].class, int.class)
        .invoke(null, scalar, 0, point, 0, result, 0);
      return result;
    } catch (Exception e) {
      throw new RuntimeException("BC X25519 failed: " + e.getMessage(), e);
    }
  }

  public String getName() { return "Bouncy Castle"; }

  public boolean isKEMSupported(int algId) {
    return kemParamField(algId) != null;
  }
}
