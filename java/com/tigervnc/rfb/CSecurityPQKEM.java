/* Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Post-Quantum KEM security handler for the VNC Java viewer.
 * Implements the QuantaVNC PQKEM handshake protocol:
 *   ML-KEM (FIPS 203) + X25519 hybrid key exchange
 *   ML-DSA (FIPS 204) server authentication
 *   AES-256-EAX authenticated channel encryption
 *
 * Wire-compatible with the C++ QuantaVNC server.
 */

package com.tigervnc.rfb;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.swing.JOptionPane;

import com.tigervnc.rdr.*;
import com.tigervnc.vncviewer.*;

public class CSecurityPQKEM extends CSecurity {

  private static LogWriter vlog = new LogWriter("CSecurityPQKEM");

  // PQC KEM algorithm IDs (match C++ PQCAlgorithm.h)
  public static final int ALG_MLKEM_512  = 1;
  public static final int ALG_MLKEM_768  = 2;
  public static final int ALG_MLKEM_1024 = 3;

  // PQC DSA algorithm IDs (match C++ PQCSignature.h)
  public static final int ALG_MLDSA_44 = 1;
  public static final int ALG_MLDSA_65 = 2;
  public static final int ALG_MLDSA_87 = 3;

  // RA2 subtypes for credential exchange
  private static final int SUBTYPE_USERPASS = 1;
  private static final int SUBTYPE_PASS    = 2;

  private final int secType;
  private final boolean isAllEncrypted;
  private final PQCProvider pqc;

  // Protocol state
  private int selectedAlg;
  private byte[] serverKEMPubKey;
  private byte[] serverX25519Public;
  private byte[] kemCiphertext;
  private byte[] kemSharedSecret;
  private byte[] clientX25519Private;
  private byte[] clientX25519Public;
  private byte[] ecdhSharedSecret;

  // ML-DSA server authentication
  private int serverDSAAlgId;
  private byte[] serverDSAPubKey;

  // Encrypted streams
  private AESInStream rais;
  private AESOutStream raos;

  public CSecurityPQKEM(int secType, boolean isAllEncrypted) {
    this.secType = secType;
    this.isAllEncrypted = isAllEncrypted;
    this.pqc = PQCProviderFactory.create();
    if (pqc == null)
      throw new Exception("No PQC cryptographic provider available. " +
        "Please add Bouncy Castle (bcprov + bcpqc JARs) or liboqs-java to the classpath.");
    vlog.info("Using PQC provider: " + pqc.getName());
  }

  public boolean processMsg(CConnection cc) {
    readServerPublicKeys(cc);
    readServerSignature(cc);
    verifyServer();
    writeEncapsulation(cc);
    setCipher(cc);
    writeHash();
    readHash();
    readSubtype();
    writeCredentials();
    return true;
  }

  // Step 1: Read algorithm negotiation + server KEM + X25519 public keys
  private void readServerPublicKeys(CConnection cc) {
    InStream is = cc.getInStream();

    // Read algorithm negotiation
    int numAlgs = is.readU8();
    if (numAlgs == 0 || numAlgs > 16)
      throw new AuthFailureException("Invalid PQC algorithm count");

    int[] serverAlgs = new int[numAlgs];
    for (int i = 0; i < numAlgs; i++)
      serverAlgs[i] = is.readU8();

    selectedAlg = is.readU8();

    if (!pqc.isKEMSupported(selectedAlg))
      throw new AuthFailureException("Server selected unsupported PQC algorithm: " + selectedAlg);

    vlog.info("PQC negotiation: server selected " + kemAlgName(selectedAlg) +
              " (" + numAlgs + " algorithm(s) offered)");

    // Read public keys
    int pubKeyLen = is.readU16();
    if (pubKeyLen == 0 || pubKeyLen > 4096)
      throw new AuthFailureException("Invalid KEM public key length: " + pubKeyLen);

    serverKEMPubKey = new byte[pubKeyLen];
    is.readBytes(ByteBuffer.wrap(serverKEMPubKey), pubKeyLen);

    serverX25519Public = new byte[32];
    is.readBytes(ByteBuffer.wrap(serverX25519Public), 32);

    vlog.info("Received server KEM public key (" + pubKeyLen + " bytes) and X25519 key");
  }

  // Step 2: Read ML-DSA signature and public key
  private void readServerSignature(CConnection cc) {
    InStream is = cc.getInStream();

    serverDSAAlgId = is.readU8();

    int pkLen = is.readU16();
    if (pkLen == 0 || pkLen > 16384)
      throw new AuthFailureException("Invalid ML-DSA public key length");

    serverDSAPubKey = new byte[pkLen];
    is.readBytes(ByteBuffer.wrap(serverDSAPubKey), pkLen);

    int sigLen = is.readU16();
    if (sigLen == 0 || sigLen > 16384)
      throw new AuthFailureException("Invalid ML-DSA signature length");

    byte[] signature = new byte[sigLen];
    is.readBytes(ByteBuffer.wrap(signature), sigLen);

    // Reconstruct signed message: SHA-256(selectedAlg || kemPubKey || serverX25519Public)
    byte[] msgHash = sha256(
      new byte[]{ (byte) selectedAlg },
      serverKEMPubKey,
      serverX25519Public
    );

    // Verify signature
    boolean valid = pqc.dsaVerify(serverDSAAlgId, serverDSAPubKey, msgHash, signature);
    if (!valid)
      throw new AuthFailureException("ML-DSA signature verification failed - " +
        "server identity cannot be authenticated");

    vlog.info("ML-DSA-" + dsaAlgName(serverDSAAlgId) + " signature verified successfully");
  }

  // Step 3: TOFU verification dialog
  private void verifyServer() {
    byte[] hash = sha256(serverDSAPubKey);
    String title = "Server identity verification";
    String text = String.format(
      "The server has provided the following ML-DSA identity:\n" +
      "Algorithm: %s\n" +
      "Fingerprint: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n\n" +
      "The server's ephemeral key exchange has been cryptographically " +
      "authenticated with this identity.\n" +
      "Please verify that the fingerprint is correct and press \"Yes\". " +
      "Otherwise press \"No\"",
      dsaAlgName(serverDSAAlgId),
      hash[0] & 0xFF, hash[1] & 0xFF, hash[2] & 0xFF, hash[3] & 0xFF,
      hash[4] & 0xFF, hash[5] & 0xFF, hash[6] & 0xFF, hash[7] & 0xFF);
    if (!msg.showMsgBox(JOptionPane.YES_NO_OPTION, title, text))
      throw new AuthFailureException("Server identity rejected by user");
  }

  // Step 4: ML-KEM encapsulation + X25519 ECDH, send to server
  private void writeEncapsulation(CConnection cc) {
    OutStream os = cc.getOutStream();

    // ML-KEM encapsulation
    PQCProvider.KEMEncapsResult result = pqc.kemEncapsulate(selectedAlg, serverKEMPubKey);
    kemCiphertext = result.ciphertext;
    kemSharedSecret = result.sharedSecret;

    // X25519 key generation
    clientX25519Private = X25519.generatePrivateKey();
    clientX25519Public = X25519.publicKey(clientX25519Private);

    // ECDH shared secret
    ecdhSharedSecret = X25519.scalarMult(clientX25519Private, serverX25519Public);

    // Send: U16(ciphertextLen) || ciphertext || clientX25519Public(32)
    os.writeU16(kemCiphertext.length);
    os.writeBytes(kemCiphertext, 0, kemCiphertext.length);
    os.writeBytes(clientX25519Public, 0, 32);
    os.flush();

    vlog.info("Sent KEM ciphertext (" + kemCiphertext.length + " bytes) and X25519 public key");
  }

  // Step 5: Derive AES-256-EAX keys and install encrypted streams
  private void setCipher(CConnection cc) {
    // C2S key = SHA-256(kemSharedSecret || ecdhSharedSecret || U8(selectedAlg) || "QuantaVNC-PQKEM-C2S")
    byte[] c2sKey = sha256(
      kemSharedSecret,
      ecdhSharedSecret,
      new byte[]{ (byte) selectedAlg },
      "QuantaVNC-PQKEM-C2S".getBytes()
    );

    // S2C key = SHA-256(kemSharedSecret || ecdhSharedSecret || U8(selectedAlg) || "QuantaVNC-PQKEM-S2C")
    byte[] s2cKey = sha256(
      kemSharedSecret,
      ecdhSharedSecret,
      new byte[]{ (byte) selectedAlg },
      "QuantaVNC-PQKEM-S2C".getBytes()
    );

    rais = new AESInStream(cc.getInStream(), s2cKey);
    raos = new AESOutStream(cc.getOutStream(), c2sKey);

    if (isAllEncrypted)
      cc.setStreams(rais, raos);
  }

  // Step 6: Send transcript hash to server (encrypted)
  private void writeHash() {
    // SHA-256(U8(selectedAlg) || kemCiphertext || clientX25519Public ||
    //         serverKEMPubKey || serverX25519Public)
    byte[] hash = sha256(
      new byte[]{ (byte) selectedAlg },
      kemCiphertext,
      clientX25519Public,
      serverKEMPubKey,
      serverX25519Public
    );
    raos.writeBytes(hash, 0, 32);
    raos.flush();
  }

  // Step 7: Read and verify server's transcript hash (encrypted)
  private void readHash() {
    ByteBuffer buf = ByteBuffer.allocate(32);
    rais.readBytes(buf, 32);
    byte[] hash = buf.array();

    // Expected: SHA-256(U8(selectedAlg) || serverKEMPubKey || serverX25519Public ||
    //                    kemCiphertext || clientX25519Public)
    byte[] expected = sha256(
      new byte[]{ (byte) selectedAlg },
      serverKEMPubKey,
      serverX25519Public,
      kemCiphertext,
      clientX25519Public
    );

    if (!Arrays.equals(hash, expected))
      throw new AuthFailureException("Server transcript hash doesn't match");

    // Clear secrets now that channel is established
    clearSecrets();
  }

  // Step 8: Read credential subtype
  private void readSubtype() {
    int subtype = rais.readU8();
    if (subtype != SUBTYPE_USERPASS && subtype != SUBTYPE_PASS)
      throw new AuthFailureException("Unknown PQKEM subtype: " + subtype);
  }

  // Step 9: Send credentials (encrypted)
  private void writeCredentials() {
    StringBuffer username = new StringBuffer();
    StringBuffer password = new StringBuffer();
    CSecurity.upg.getUserPasswd(true, username, password);

    byte[] usernameBytes;
    byte[] passwordBytes;
    try {
      usernameBytes = username.toString().getBytes("UTF-8");
      passwordBytes = password.toString().getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new AuthFailureException("UTF-8 is not supported");
    }

    if (usernameBytes.length > 255)
      throw new AuthFailureException("Username is too long");
    raos.writeU8(usernameBytes.length);
    if (usernameBytes.length > 0)
      raos.writeBytes(usernameBytes, 0, usernameBytes.length);

    if (passwordBytes.length > 255)
      throw new AuthFailureException("Password is too long");
    raos.writeU8(passwordBytes.length);
    if (passwordBytes.length > 0)
      raos.writeBytes(passwordBytes, 0, passwordBytes.length);
    raos.flush();
  }

  private void clearSecrets() {
    if (kemSharedSecret != null) { Arrays.fill(kemSharedSecret, (byte) 0); kemSharedSecret = null; }
    if (ecdhSharedSecret != null) { Arrays.fill(ecdhSharedSecret, (byte) 0); ecdhSharedSecret = null; }
    if (clientX25519Private != null) { Arrays.fill(clientX25519Private, (byte) 0); clientX25519Private = null; }
  }

  public int getType() { return secType; }
  public String description() { return "PQ-KEM (" + kemAlgName(selectedAlg) + " + X25519)"; }
  public boolean isSecure() { return true; }

  // --- Utility methods ---

  /** SHA-256 hash of concatenated byte arrays */
  private static byte[] sha256(byte[]... inputs) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      for (byte[] input : inputs)
        md.update(input);
      return md.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available");
    }
  }

  private static String kemAlgName(int algId) {
    switch (algId) {
      case ALG_MLKEM_512:  return "ML-KEM-512";
      case ALG_MLKEM_768:  return "ML-KEM-768";
      case ALG_MLKEM_1024: return "ML-KEM-1024";
      default: return "Unknown-" + algId;
    }
  }

  private static String dsaAlgName(int algId) {
    switch (algId) {
      case ALG_MLDSA_44: return "ML-DSA-44";
      case ALG_MLDSA_65: return "ML-DSA-65";
      case ALG_MLDSA_87: return "ML-DSA-87";
      default: return "Unknown-" + algId;
    }
  }
}
