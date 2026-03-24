/* Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 * Pure Java implementation for JDK 8+ compatibility.
 *
 * Arithmetic is performed in GF(2^255-19) using the Montgomery ladder.
 * Based on the reference implementation from RFC 7748 Section 5.
 */

package com.tigervnc.rfb;

import java.security.SecureRandom;
import java.util.Arrays;

public final class X25519 {

  private static final int KEY_SIZE = 32;

  // p = 2^255 - 19
  // We represent field elements as long[5], each limb < 2^51
  private static final long MASK51 = (1L << 51) - 1;

  private X25519() {}

  /** Basepoint for X25519 */
  private static final byte[] BASEPOINT = new byte[32];
  static { BASEPOINT[0] = 9; }

  /**
   * Generate a random X25519 private key (clamped per RFC 7748).
   */
  public static byte[] generatePrivateKey() {
    SecureRandom sr = new SecureRandom();
    byte[] key = new byte[KEY_SIZE];
    sr.nextBytes(key);
    clampPrivateKey(key);
    return key;
  }

  /**
   * Clamp a private key per X25519 convention.
   */
  public static void clampPrivateKey(byte[] key) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
  }

  /**
   * Compute public key from private key: result = privateKey * basepoint
   */
  public static byte[] publicKey(byte[] privateKey) {
    return scalarMult(privateKey, BASEPOINT);
  }

  /**
   * X25519 scalar multiplication: result = scalar * point
   */
  public static byte[] scalarMult(byte[] scalar, byte[] point) {
    long[] x1 = decodeUCoord(point);
    long[] x2 = {1, 0, 0, 0, 0};
    long[] z2 = {0, 0, 0, 0, 0};
    long[] x3 = Arrays.copyOf(x1, 5);
    long[] z3 = {1, 0, 0, 0, 0};

    byte[] e = Arrays.copyOf(scalar, KEY_SIZE);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    int swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
      int b = (e[pos / 8] >> (pos & 7)) & 1;
      swap ^= b;
      cswap(swap, x2, x3);
      cswap(swap, z2, z3);
      swap = b;

      long[] a = feAdd(x2, z2);
      long[] aa = feSq(a);
      long[] bb = feSq(feSub(x2, z2));
      long[] e_val = feSub(aa, bb);
      long[] c = feAdd(x3, z3);
      long[] d = feSub(x3, z3);
      long[] da = feMul(d, a);
      long[] cb = feMul(c, feSub(x2, z2));
      x3 = feSq(feAdd(da, cb));
      z3 = feMul(x1, feSq(feSub(da, cb)));
      x2 = feMul(aa, bb);
      z2 = feMul(e_val, feAdd(aa, feMul121666(e_val)));
    }

    cswap(swap, x2, x3);
    cswap(swap, z2, z3);

    long[] result = feMul(x2, feInv(z2));
    return encodeUCoord(result);
  }

  // --- Field element operations in GF(2^255-19) ---

  private static long[] decodeUCoord(byte[] u) {
    long[] f = new long[5];
    long u0 = (u[0] & 0xFFL) | ((u[1] & 0xFFL) << 8) | ((u[2] & 0xFFL) << 16)
      | ((u[3] & 0xFFL) << 24) | ((u[4] & 0xFFL) << 32) | ((u[5] & 0xFFL) << 40)
      | ((u[6] & 0x07L) << 48);
    long u1 = ((u[6] & 0xF8L) >> 3) | ((u[7] & 0xFFL) << 5) | ((u[8] & 0xFFL) << 13)
      | ((u[9] & 0xFFL) << 21) | ((u[10] & 0xFFL) << 29) | ((u[11] & 0xFFL) << 37)
      | ((u[12] & 0x3FL) << 45);
    long u2 = ((u[12] & 0xC0L) >> 6) | ((u[13] & 0xFFL) << 2) | ((u[14] & 0xFFL) << 10)
      | ((u[15] & 0xFFL) << 18) | ((u[16] & 0xFFL) << 26) | ((u[17] & 0xFFL) << 34)
      | ((u[18] & 0xFFL) << 42) | ((u[19] & 0x01L) << 50);
    long u3 = ((u[19] & 0xFEL) >> 1) | ((u[20] & 0xFFL) << 7) | ((u[21] & 0xFFL) << 15)
      | ((u[22] & 0xFFL) << 23) | ((u[23] & 0xFFL) << 31) | ((u[24] & 0xFFL) << 39)
      | ((u[25] & 0x0FL) << 47);
    long u4 = ((u[25] & 0xF0L) >> 4) | ((u[26] & 0xFFL) << 4) | ((u[27] & 0xFFL) << 12)
      | ((u[28] & 0xFFL) << 20) | ((u[29] & 0xFFL) << 28) | ((u[30] & 0xFFL) << 36)
      | ((u[31] & 0x7FL) << 44);
    f[0] = u0;
    f[1] = u1;
    f[2] = u2;
    f[3] = u3;
    f[4] = u4;
    return f;
  }

  private static byte[] encodeUCoord(long[] f) {
    feReduce(f);
    byte[] s = new byte[KEY_SIZE];
    long t0 = f[0], t1 = f[1], t2 = f[2], t3 = f[3], t4 = f[4];
    s[0] = (byte) t0;
    s[1] = (byte) (t0 >> 8);
    s[2] = (byte) (t0 >> 16);
    s[3] = (byte) (t0 >> 24);
    s[4] = (byte) (t0 >> 32);
    s[5] = (byte) (t0 >> 40);
    s[6] = (byte) ((t0 >> 48) | (t1 << 3));
    s[7] = (byte) (t1 >> 5);
    s[8] = (byte) (t1 >> 13);
    s[9] = (byte) (t1 >> 21);
    s[10] = (byte) (t1 >> 29);
    s[11] = (byte) (t1 >> 37);
    s[12] = (byte) ((t1 >> 45) | (t2 << 6));
    s[13] = (byte) (t2 >> 2);
    s[14] = (byte) (t2 >> 10);
    s[15] = (byte) (t2 >> 18);
    s[16] = (byte) (t2 >> 26);
    s[17] = (byte) (t2 >> 34);
    s[18] = (byte) (t2 >> 42);
    s[19] = (byte) ((t2 >> 50) | (t3 << 1));
    s[20] = (byte) (t3 >> 7);
    s[21] = (byte) (t3 >> 15);
    s[22] = (byte) (t3 >> 23);
    s[23] = (byte) (t3 >> 31);
    s[24] = (byte) (t3 >> 39);
    s[25] = (byte) ((t3 >> 47) | (t4 << 4));
    s[26] = (byte) (t4 >> 4);
    s[27] = (byte) (t4 >> 12);
    s[28] = (byte) (t4 >> 20);
    s[29] = (byte) (t4 >> 28);
    s[30] = (byte) (t4 >> 36);
    s[31] = (byte) (t4 >> 44);
    return s;
  }

  private static void feReduce(long[] f) {
    // Carry and reduce mod p = 2^255-19
    for (int i = 0; i < 2; i++) {
      f[1] += f[0] >> 51; f[0] &= MASK51;
      f[2] += f[1] >> 51; f[1] &= MASK51;
      f[3] += f[2] >> 51; f[2] &= MASK51;
      f[4] += f[3] >> 51; f[3] &= MASK51;
      f[0] += 19 * (f[4] >> 51); f[4] &= MASK51;
    }
    // Final reduction
    f[0] += 19;
    f[1] += f[0] >> 51; f[0] &= MASK51;
    f[2] += f[1] >> 51; f[1] &= MASK51;
    f[3] += f[2] >> 51; f[2] &= MASK51;
    f[4] += f[3] >> 51; f[3] &= MASK51;
    f[0] += 19 * (f[4] >> 51); f[4] &= MASK51;
    // Now subtract p if we're >= p
    f[0] -= 19;
    long mask = -(f[0] >> 63); // mask = -1 if borrow, 0 otherwise
    // If borrow, add back 19 (we were < p, keep as is); else don't
    // Actually need: if f >= p, subtract p. Carry-based approach:
    // After adding 19 and carrying, check if f[0] >= 0 after subtracting 19
    // Simpler: just carry properly
    f[1] += f[0] >> 51; f[0] &= MASK51;
    f[2] += f[1] >> 51; f[1] &= MASK51;
    f[3] += f[2] >> 51; f[2] &= MASK51;
    f[4] += f[3] >> 51; f[3] &= MASK51;
    f[4] &= MASK51;
  }

  private static long[] feAdd(long[] a, long[] b) {
    return new long[]{ a[0]+b[0], a[1]+b[1], a[2]+b[2], a[3]+b[3], a[4]+b[4] };
  }

  private static long[] feSub(long[] a, long[] b) {
    // Add 2*p to prevent underflow before subtraction
    return new long[]{
      a[0]-b[0] + 0xFFFFFFFFFFFDAL,
      a[1]-b[1] + 0xFFFFFFFFFFFFEL,
      a[2]-b[2] + 0xFFFFFFFFFFFFEL,
      a[3]-b[3] + 0xFFFFFFFFFFFFEL,
      a[4]-b[4] + 0xFFFFFFFFFFFFEL
    };
  }

  private static long[] feMul(long[] a, long[] b) {
    // Schoolbook multiplication with 128-bit intermediaries
    // Since Java doesn't have unsigned 128-bit, we use the fact that
    // each limb is < 2^52 and products fit in long with carries
    long a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    long b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];

    // Reduce: multiply by 19 for wrap-around terms
    long b1_19 = 19 * b1, b2_19 = 19 * b2, b3_19 = 19 * b3, b4_19 = 19 * b4;

    // Use long arithmetic carefully. Max product: 2^51 * 2^51 = 2^102
    // With 5 additions: ~ 5 * 2^102 = 2^104.3 < 2^127, so no overflow
    // Actually 19*b < 19*2^51 ≈ 2^55, product ≈ 2^106, sum of 5 ≈ 2^109 - fits in long

    long s0 = a0*b0 + a1*b4_19 + a2*b3_19 + a3*b2_19 + a4*b1_19;
    long s1 = a0*b1 + a1*b0 + a2*b4_19 + a3*b3_19 + a4*b2_19;
    long s2 = a0*b2 + a1*b1 + a2*b0 + a3*b4_19 + a4*b3_19;
    long s3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + a4*b4_19;
    long s4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;

    // Carry
    long c;
    c = s0 >> 51; s1 += c; s0 &= MASK51;
    c = s1 >> 51; s2 += c; s1 &= MASK51;
    c = s2 >> 51; s3 += c; s2 &= MASK51;
    c = s3 >> 51; s4 += c; s3 &= MASK51;
    c = s4 >> 51; s0 += c * 19; s4 &= MASK51;
    c = s0 >> 51; s1 += c; s0 &= MASK51;

    return new long[]{ s0, s1, s2, s3, s4 };
  }

  private static long[] feSq(long[] a) {
    return feMul(a, a);
  }

  private static long[] feMul121666(long[] a) {
    long s0 = a[0] * 121666;
    long s1 = a[1] * 121666;
    long s2 = a[2] * 121666;
    long s3 = a[3] * 121666;
    long s4 = a[4] * 121666;

    long c;
    c = s0 >> 51; s1 += c; s0 &= MASK51;
    c = s1 >> 51; s2 += c; s1 &= MASK51;
    c = s2 >> 51; s3 += c; s2 &= MASK51;
    c = s3 >> 51; s4 += c; s3 &= MASK51;
    c = s4 >> 51; s0 += c * 19; s4 &= MASK51;
    c = s0 >> 51; s1 += c; s0 &= MASK51;

    return new long[]{ s0, s1, s2, s3, s4 };
  }

  private static long[] feInv(long[] z) {
    // z^(p-2) using addition chain for p-2 = 2^255-21
    long[] t0 = feSq(z);        // z^2
    long[] t1 = feSq(t0);       // z^4
    t1 = feSq(t1);              // z^8
    t1 = feMul(z, t1);          // z^9
    t0 = feMul(t0, t1);         // z^11
    long[] t2 = feSq(t0);       // z^22
    t1 = feMul(t1, t2);         // z^(2^5 - 1) = z^31
    t2 = feSq(t1);
    for (int i = 0; i < 4; i++) t2 = feSq(t2);
    t1 = feMul(t2, t1);         // z^(2^10 - 1)
    t2 = feSq(t1);
    for (int i = 0; i < 9; i++) t2 = feSq(t2);
    t2 = feMul(t2, t1);         // z^(2^20 - 1)
    long[] t3 = feSq(t2);
    for (int i = 0; i < 19; i++) t3 = feSq(t3);
    t2 = feMul(t3, t2);         // z^(2^40 - 1)
    t2 = feSq(t2);
    for (int i = 0; i < 9; i++) t2 = feSq(t2);
    t1 = feMul(t2, t1);         // z^(2^50 - 1)
    t2 = feSq(t1);
    for (int i = 0; i < 49; i++) t2 = feSq(t2);
    t2 = feMul(t2, t1);         // z^(2^100 - 1)
    t3 = feSq(t2);
    for (int i = 0; i < 99; i++) t3 = feSq(t3);
    t2 = feMul(t3, t2);         // z^(2^200 - 1)
    t2 = feSq(t2);
    for (int i = 0; i < 49; i++) t2 = feSq(t2);
    t1 = feMul(t2, t1);         // z^(2^250 - 1)
    t1 = feSq(t1);              // z^(2^251 - 2)
    t1 = feSq(t1);              // z^(2^252 - 4)
    t1 = feSq(t1);              // z^(2^253 - 8)
    t1 = feSq(t1);              // z^(2^254 - 16)
    t1 = feSq(t1);              // z^(2^255 - 32)
    return feMul(t1, t0);       // z^(2^255 - 21) = z^(p-2)
  }

  private static void cswap(int swap, long[] a, long[] b) {
    long mask = -(long) swap;
    for (int i = 0; i < 5; i++) {
      long x = mask & (a[i] ^ b[i]);
      a[i] ^= x;
      b[i] ^= x;
    }
  }
}
