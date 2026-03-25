/*
 * QuantaVNC - Post-Quantum Cryptography VNC Platform
 * Copyright (C) 2026 Dyber, Inc.
 *
 * PQC Performance Benchmarks
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

#ifdef HAVE_LIBOQS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <chrono>
#include <vector>
#include <string>

#include <oqs/oqs.h>

#ifdef HAVE_NETTLE
#include <nettle/eax.h>
#include <nettle/aes.h>
#include <nettle/curve25519.h>
#endif

#include "util.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static const int WARMUP_ITERS = 5;
static const double MIN_BENCH_SECONDS = 1.0;

struct BenchResult {
  std::string name;
  std::string operation;
  double opsPerSec;
  double avgUs;        // microseconds per operation
  int    iterations;
  size_t pk_bytes;     // 0 if not applicable
  size_t sk_bytes;
  size_t ct_bytes;     // ciphertext or signature size
};

static std::vector<BenchResult> results;

static double now_sec()
{
  using namespace std::chrono;
  return duration<double>(steady_clock::now().time_since_epoch()).count();
}

// Run func repeatedly for at least MIN_BENCH_SECONDS, return ops/sec
template<typename Func>
static BenchResult benchOp(const char* name, const char* operation,
                           Func func, size_t pk = 0, size_t sk = 0,
                           size_t ct = 0)
{
  // Warmup
  for (int i = 0; i < WARMUP_ITERS; i++)
    func();

  int iters = 0;
  double start = now_sec();
  double elapsed = 0;

  while (elapsed < MIN_BENCH_SECONDS) {
    func();
    iters++;
    elapsed = now_sec() - start;
  }

  BenchResult r;
  r.name = name;
  r.operation = operation;
  r.opsPerSec = (double)iters / elapsed;
  r.avgUs = (elapsed / (double)iters) * 1e6;
  r.iterations = iters;
  r.pk_bytes = pk;
  r.sk_bytes = sk;
  r.ct_bytes = ct;
  results.push_back(r);
  return r;
}

// ---------------------------------------------------------------------------
// ML-KEM benchmarks
// ---------------------------------------------------------------------------

static void benchKEM(const char* algName, const char* displayName)
{
  OQS_KEM* kem = OQS_KEM_new(algName);
  if (!kem) {
    fprintf(stderr, "WARNING: %s not available, skipping\n", displayName);
    return;
  }

  size_t pk_len = kem->length_public_key;
  size_t sk_len = kem->length_secret_key;
  size_t ct_len = kem->length_ciphertext;
  size_t ss_len = kem->length_shared_secret;

  uint8_t* pk = (uint8_t*)malloc(pk_len);
  uint8_t* sk = (uint8_t*)malloc(sk_len);
  uint8_t* ct = (uint8_t*)malloc(ct_len);
  uint8_t* ss_enc = (uint8_t*)malloc(ss_len);
  uint8_t* ss_dec = (uint8_t*)malloc(ss_len);

  // Keygen benchmark
  benchOp(displayName, "keygen", [&]() {
    OQS_KEM_keypair(kem, pk, sk);
  }, pk_len, sk_len, ct_len);

  // Generate a keypair for encaps/decaps
  OQS_KEM_keypair(kem, pk, sk);

  // Encapsulation benchmark
  benchOp(displayName, "encaps", [&]() {
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
  }, pk_len, sk_len, ct_len);

  // Generate a fresh ciphertext for decaps
  OQS_KEM_encaps(kem, ct, ss_enc, pk);

  // Decapsulation benchmark
  benchOp(displayName, "decaps", [&]() {
    OQS_KEM_decaps(kem, ss_dec, ct, sk);
  }, pk_len, sk_len, ct_len);

  free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
  OQS_KEM_free(kem);
}

// ---------------------------------------------------------------------------
// ML-DSA benchmarks
// ---------------------------------------------------------------------------

static void benchSig(const char* algName, const char* displayName)
{
  OQS_SIG* sig = OQS_SIG_new(algName);
  if (!sig) {
    fprintf(stderr, "WARNING: %s not available, skipping\n", displayName);
    return;
  }

  size_t pk_len = sig->length_public_key;
  size_t sk_len = sig->length_secret_key;
  size_t sig_len = sig->length_signature;

  uint8_t* pk = (uint8_t*)malloc(pk_len);
  uint8_t* sk = (uint8_t*)malloc(sk_len);
  uint8_t* signature = (uint8_t*)malloc(sig_len);
  size_t actual_sig_len = 0;

  // Message to sign (32 bytes, typical hash size)
  uint8_t msg[32];
  memset(msg, 0x42, sizeof(msg));

  // Keygen benchmark
  benchOp(displayName, "keygen", [&]() {
    OQS_SIG_keypair(sig, pk, sk);
  }, pk_len, sk_len, sig_len);

  // Generate keypair for sign/verify
  OQS_SIG_keypair(sig, pk, sk);

  // Sign benchmark
  benchOp(displayName, "sign", [&]() {
    OQS_SIG_sign(sig, signature, &actual_sig_len, msg, sizeof(msg), sk);
  }, pk_len, sk_len, sig_len);

  // Sign once for verify
  OQS_SIG_sign(sig, signature, &actual_sig_len, msg, sizeof(msg), sk);

  // Verify benchmark
  benchOp(displayName, "verify", [&]() {
    OQS_SIG_verify(sig, msg, sizeof(msg), signature, actual_sig_len, pk);
  }, pk_len, sk_len, sig_len);

  free(pk); free(sk); free(signature);
  OQS_SIG_free(sig);
}

// ---------------------------------------------------------------------------
// X25519 benchmark
// ---------------------------------------------------------------------------

#ifdef HAVE_NETTLE
static void benchX25519()
{
  static const uint8_t basepoint[CURVE25519_SIZE] = { 9 };
  uint8_t privkey[CURVE25519_SIZE];
  uint8_t pubkey[CURVE25519_SIZE];
  uint8_t shared[CURVE25519_SIZE];

  // Fill private key with deterministic data
  for (int i = 0; i < CURVE25519_SIZE; i++)
    privkey[i] = (uint8_t)(i + 1);
  // Clamp
  privkey[0] &= 248;
  privkey[31] &= 127;
  privkey[31] |= 64;

  curve25519_mul(pubkey, privkey, basepoint);

  benchOp("X25519", "scalar_mul", [&]() {
    curve25519_mul(shared, privkey, pubkey);
  }, CURVE25519_SIZE, CURVE25519_SIZE, 0);
}

// ---------------------------------------------------------------------------
// AES-256-EAX benchmark
// ---------------------------------------------------------------------------

static void benchAES256EAX()
{
  static const int BLOCK_SIZE = 8192;

  uint8_t key[32];
  uint8_t nonce[16];
  uint8_t plaintext[BLOCK_SIZE];
  uint8_t ciphertext[BLOCK_SIZE];
  uint8_t tag[EAX_DIGEST_SIZE];
  struct eax_aes256_ctx ctx;

  memset(key, 0xAA, sizeof(key));
  memset(nonce, 0xBB, sizeof(nonce));
  memset(plaintext, 0xCC, sizeof(plaintext));

  eax_aes256_set_key(&ctx, key);

  // Encrypt throughput
  BenchResult encR = benchOp("AES-256-EAX", "encrypt", [&]() {
    eax_aes256_set_nonce(&ctx, sizeof(nonce), nonce);
    eax_aes256_encrypt(&ctx, sizeof(plaintext), ciphertext, plaintext);
    eax_aes256_digest(&ctx, sizeof(tag), tag);
  });
  // Override ops/sec with MB/s
  double encMBs = (encR.opsPerSec * BLOCK_SIZE) / (1024.0 * 1024.0);

  // Decrypt throughput
  eax_aes256_set_nonce(&ctx, sizeof(nonce), nonce);
  eax_aes256_encrypt(&ctx, sizeof(plaintext), ciphertext, plaintext);
  eax_aes256_digest(&ctx, sizeof(tag), tag);

  BenchResult decR = benchOp("AES-256-EAX", "decrypt", [&]() {
    eax_aes256_set_nonce(&ctx, sizeof(nonce), nonce);
    eax_aes256_decrypt(&ctx, sizeof(ciphertext), plaintext, ciphertext);
    eax_aes256_digest(&ctx, sizeof(tag), tag);
  });
  double decMBs = (decR.opsPerSec * BLOCK_SIZE) / (1024.0 * 1024.0);

  // Patch the last two results to show MB/s in a special field
  // We store MB/s in the opsPerSec field for AES entries (flagged by name)
  results[results.size() - 2].opsPerSec = encMBs;
  results[results.size() - 2].ct_bytes = BLOCK_SIZE;
  results[results.size() - 1].opsPerSec = decMBs;
  results[results.size() - 1].ct_bytes = BLOCK_SIZE;
}

// ---------------------------------------------------------------------------
// Full hybrid handshake benchmark (KEM + ECDH + KDF simulation)
// ---------------------------------------------------------------------------

static void benchHybridHandshake()
{
  OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    fprintf(stderr, "WARNING: ML-KEM-768 not available, skipping hybrid\n");
    return;
  }

  static const uint8_t basepoint[CURVE25519_SIZE] = { 9 };

  size_t pk_len = kem->length_public_key;
  size_t sk_len = kem->length_secret_key;
  size_t ct_len = kem->length_ciphertext;
  size_t ss_len = kem->length_shared_secret;

  uint8_t* pk = (uint8_t*)malloc(pk_len);
  uint8_t* sk = (uint8_t*)malloc(sk_len);
  uint8_t* ct = (uint8_t*)malloc(ct_len);
  uint8_t* ss = (uint8_t*)malloc(ss_len);

  uint8_t privA[CURVE25519_SIZE], pubA[CURVE25519_SIZE];
  uint8_t privB[CURVE25519_SIZE], pubB[CURVE25519_SIZE];
  uint8_t ecdhShared[CURVE25519_SIZE];

  // Prepare X25519 keys
  for (int i = 0; i < CURVE25519_SIZE; i++) {
    privA[i] = (uint8_t)(i + 1);
    privB[i] = (uint8_t)(i + 0x80);
  }
  privA[0] &= 248; privA[31] &= 127; privA[31] |= 64;
  privB[0] &= 248; privB[31] &= 127; privB[31] |= 64;

  curve25519_mul(pubA, privA, basepoint);
  curve25519_mul(pubB, privB, basepoint);

  // Full handshake: server keygen + client encaps + server decaps + ECDH
  benchOp("Hybrid", "handshake(KEM+ECDH)", [&]() {
    // Server generates KEM keypair
    OQS_KEM_keypair(kem, pk, sk);
    // Server generates X25519 public key (already done, simulate)
    curve25519_mul(pubB, privB, basepoint);
    // Client encapsulates
    OQS_KEM_encaps(kem, ct, ss, pk);
    // Client computes X25519 shared secret
    curve25519_mul(ecdhShared, privA, pubB);
    // Server decapsulates
    OQS_KEM_decaps(kem, ss, ct, sk);
    // Server computes X25519 shared secret
    curve25519_mul(ecdhShared, privB, pubA);
    // KDF would combine ss + ecdhShared (omitted, negligible cost)
  });

  free(pk); free(sk); free(ct); free(ss);
  OQS_KEM_free(kem);
}

#endif // HAVE_NETTLE

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

static void printTable()
{
  printf("\n");
  printf("=============================================================");
  printf("============================\n");
  printf("QuantaVNC PQC Performance Benchmarks\n");
  printf("=============================================================");
  printf("============================\n\n");

  printf("%-16s %-22s %12s %12s %8s %8s %8s\n",
         "Algorithm", "Operation", "ops/sec", "us/op",
         "PK(B)", "SK(B)", "CT/Sig(B)");
  printf("%-16s %-22s %12s %12s %8s %8s %8s\n",
         "----------------", "----------------------",
         "------------", "------------",
         "--------", "--------", "---------");

  for (const auto& r : results) {
    bool isAES = (r.name.find("AES") != std::string::npos);

    if (isAES) {
      printf("%-16s %-22s %9.1f MB/s %12.2f %8s %8s %8zu\n",
             r.name.c_str(), r.operation.c_str(),
             r.opsPerSec, r.avgUs, "-", "-", r.ct_bytes);
    } else if (r.pk_bytes > 0) {
      printf("%-16s %-22s %12.1f %12.2f %8zu %8zu %8zu\n",
             r.name.c_str(), r.operation.c_str(),
             r.opsPerSec, r.avgUs,
             r.pk_bytes, r.sk_bytes, r.ct_bytes);
    } else {
      printf("%-16s %-22s %12.1f %12.2f %8s %8s %8s\n",
             r.name.c_str(), r.operation.c_str(),
             r.opsPerSec, r.avgUs, "-", "-", "-");
    }
  }

  printf("\n");
}

static void printCSV()
{
  printf("--- CSV BEGIN ---\n");
  printf("algorithm,operation,ops_per_sec,us_per_op,iterations,"
         "pk_bytes,sk_bytes,ct_sig_bytes\n");

  for (const auto& r : results) {
    printf("%s,%s,%.2f,%.2f,%d,%zu,%zu,%zu\n",
           r.name.c_str(), r.operation.c_str(),
           r.opsPerSec, r.avgUs, r.iterations,
           r.pk_bytes, r.sk_bytes, r.ct_bytes);
  }

  printf("--- CSV END ---\n");
}

// ---------------------------------------------------------------------------
// Key size report
// ---------------------------------------------------------------------------

static void printKeySizes()
{
  printf("\n");
  printf("Key/Ciphertext Sizes (bytes)\n");
  printf("%-16s %8s %10s %12s %14s\n",
         "Algorithm", "PK", "SK", "CT/Sig", "Shared Secret");
  printf("%-16s %8s %10s %12s %14s\n",
         "----------------", "--------", "----------",
         "------------", "--------------");

  struct { const char* oqs; const char* display; } kems[] = {
    { OQS_KEM_alg_ml_kem_512,  "ML-KEM-512"  },
    { OQS_KEM_alg_ml_kem_768,  "ML-KEM-768"  },
    { OQS_KEM_alg_ml_kem_1024, "ML-KEM-1024" },
  };

  for (auto& k : kems) {
    OQS_KEM* kem = OQS_KEM_new(k.oqs);
    if (kem) {
      printf("%-16s %8zu %10zu %12zu %14zu\n",
             k.display, kem->length_public_key, kem->length_secret_key,
             kem->length_ciphertext, kem->length_shared_secret);
      OQS_KEM_free(kem);
    }
  }

  struct { const char* oqs; const char* display; } sigs[] = {
    { OQS_SIG_alg_ml_dsa_44, "ML-DSA-44" },
    { OQS_SIG_alg_ml_dsa_65, "ML-DSA-65" },
    { OQS_SIG_alg_ml_dsa_87, "ML-DSA-87" },
  };

  for (auto& s : sigs) {
    OQS_SIG* sig = OQS_SIG_new(s.oqs);
    if (sig) {
      printf("%-16s %8zu %10zu %12zu %14s\n",
             s.display, sig->length_public_key, sig->length_secret_key,
             sig->length_signature, "N/A");
      OQS_SIG_free(sig);
    }
  }

#ifdef HAVE_NETTLE
  printf("%-16s %8d %10d %12s %14d\n",
         "X25519", CURVE25519_SIZE, CURVE25519_SIZE, "N/A",
         CURVE25519_SIZE);
#endif

  printf("\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int /*argc*/, char** /*argv*/)
{
  OQS_init();

  printf("liboqs version: %s\n", OQS_version());
  printf("Minimum benchmark duration per operation: %.1f seconds\n",
         MIN_BENCH_SECONDS);
  printf("\n");

  // ML-KEM benchmarks
  benchKEM(OQS_KEM_alg_ml_kem_512,  "ML-KEM-512");
  benchKEM(OQS_KEM_alg_ml_kem_768,  "ML-KEM-768");
  benchKEM(OQS_KEM_alg_ml_kem_1024, "ML-KEM-1024");

  // ML-DSA benchmarks
  benchSig(OQS_SIG_alg_ml_dsa_44, "ML-DSA-44");
  benchSig(OQS_SIG_alg_ml_dsa_65, "ML-DSA-65");
  benchSig(OQS_SIG_alg_ml_dsa_87, "ML-DSA-87");

#ifdef HAVE_NETTLE
  // X25519
  benchX25519();

  // AES-256-EAX
  benchAES256EAX();

  // Full hybrid handshake
  benchHybridHandshake();
#endif

  // Output results
  printTable();
  printKeySizes();
  printCSV();

  OQS_destroy();
  return 0;
}

#else // !HAVE_LIBOQS

#include <stdio.h>

int main()
{
  printf("PQC benchmarks require liboqs (HAVE_LIBOQS). "
         "Build with -DENABLE_PQC=ON.\n");
  return 1;
}

#endif
