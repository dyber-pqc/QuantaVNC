# Post-Quantum Cryptography Security Design

This document describes the post-quantum cryptographic design of QuantaVNC.

## Threat Model

### Harvest Now, Decrypt Later

The primary threat QuantaVNC addresses is the "harvest now, decrypt later" (HNDL) attack. An adversary with network access records encrypted VNC sessions today, then decrypts them in the future using a cryptographically relevant quantum computer (CRQC).

VNC sessions may contain sensitive data: credentials typed into remote machines, confidential documents displayed on screen, administrative operations on critical infrastructure. The contents of these sessions must remain confidential for years or decades, well into the timeframe when quantum computers capable of breaking RSA and elliptic curve cryptography may exist.

### Adversary Capabilities

QuantaVNC assumes the adversary can:

- Passively record all network traffic between client and server
- Perform active man-in-the-middle attacks (mitigated by TOFU/X.509 verification)
- Access a large-scale quantum computer at some future date

## Algorithm Choices

### ML-KEM-768 (FIPS 203)

QuantaVNC uses **ML-KEM-768** (Module-Lattice-Based Key Encapsulation Mechanism), standardized by NIST in FIPS 203. ML-KEM-768 provides:

- **NIST Security Level 3**: roughly equivalent to AES-192 against both classical and quantum adversaries
- **Performance**: key generation, encapsulation, and decapsulation each complete in under 1ms on modern hardware
- **Key sizes**: 1,184-byte public key, 2,400-byte private key, 1,088-byte ciphertext -- manageable within VNC's RFB protocol

Level 3 was chosen as the best balance between security margin and overhead. ML-KEM-512 (Level 1) provides a narrower security margin against potential future improvements in lattice attacks, while ML-KEM-1024 (Level 5) increases key and ciphertext sizes without proportional benefit for most deployment scenarios.

### Hybrid Key Exchange

QuantaVNC always performs **hybrid key exchange**, combining:

1. **X25519** (classical elliptic-curve Diffie-Hellman)
2. **ML-KEM-768** (post-quantum KEM)

The shared secret is derived from both components. This ensures:

- If ML-KEM is broken by a future classical attack, X25519 still protects the session
- If X25519 is broken by a quantum computer, ML-KEM still protects the session
- Security is never worse than the stronger of the two algorithms

This follows the recommendation of NIST, ANSSI, BSI, and other standards bodies to use hybrid constructions during the transition to post-quantum cryptography.

### AES-256-EAX

The derived shared secret protects the VNC session using **AES-256-EAX** authenticated encryption. EAX mode provides both confidentiality and integrity with a single pass over the data and is well-suited to the streaming nature of the RFB protocol.

## Protocol Description (PQKEM Security Types)

The PQKEM security type performs key exchange directly within the RFB protocol, without relying on TLS. The handshake includes algorithm negotiation and proceeds as follows:

```
Client                                         Server
  |                                               |
  |  ---- SecurityType: PQKEMVnc ---------------> |
  |                                               |
  |  <--- U8(numAlgorithms)  ---------------------- |  Algorithm
  |  <--- U8(algId) x numAlgorithms  ------------- |  negotiation
  |  <--- U8(selectedAlg)  ----------------------- |
  |                                               |
  |  <--- U16(pubKeyLen) || pk_pq  --------------- |  Key exchange
  |  <--- X25519 public key (pk_x25519) ---------- |
  |                                               |
  |  <--- U8(dsaAlgId)  -------------------------- |  Server
  |  <--- U16(dsaPubKeyLen) || dsaPubKey  --------- |  authentication
  |  <--- U16(sigLen) || ML-DSA signature  -------- |  (ML-DSA)
  |                                               |
  |  Client verifies ML-DSA signature over          |
  |    SHA-256(selectedAlg || pk_pq || pk_x25519)   |
  |  Client verifies TOFU fingerprint of dsaPubKey  |
  |                                               |
  |  ML-KEM encapsulate: (ct_pq, ss_pq) = Encaps(pk_pq)
  |  X25519 key agreement: ss_x25519 = X25519(sk, pk_x25519)
  |                                               |
  |  ---- U16(ctLen) || ct_pq  -----------------> |
  |  ---- X25519 public key (client) -----------> |
  |                                               |
  |                   Server decapsulates and derives same secrets
  |                                               |
  |  Both sides: K = KDF(ss_pq || ss_x25519 || algId || context)
  |                                               |
  |  ==== AES-256-EAX encrypted channel ========= |
  |                                               |
  |  (VNC authentication proceeds inside the      |
  |   encrypted channel if required)              |
```

### Algorithm Negotiation

The server probes liboqs at runtime to determine which ML-KEM algorithms are available:

| Algorithm ID | Algorithm | NIST Level | Public Key | Ciphertext |
|-------------|-----------|------------|------------|------------|
| 1 | ML-KEM-512 | Level 1 | 800 bytes | 768 bytes |
| 2 | ML-KEM-768 | Level 3 | 1,184 bytes | 1,088 bytes |
| 3 | ML-KEM-1024 | Level 5 | 1,568 bytes | 1,568 bytes |

The server sends its supported algorithms in preference order (strongest first), then its selected algorithm. The server generates keys for the selected algorithm. The client verifies it supports the selected algorithm or aborts the connection.

The algorithm ID is cryptographically bound into both the key derivation and the transcript hashes, preventing algorithm downgrade attacks.

### PQC Mode

Both the server and client support a `PQCMode` parameter with three values:

- **preferred** (default): PQC security types are offered/accepted first, with classical types as fallback
- **required**: Only PQC security types are accepted; connections fail if PQC is unavailable
- **off**: PQC security types are disabled; only classical types are used

The fallback cascade is: **PQKEM** (direct PQC) -> **PQTLS/PQX509** (TLS with PQ groups) -> **TLS** (classical) -> **VncAuth** (no encryption). Setting `PQCMode=required` on either side enforces PQC-only connections.

### Key Derivation

Separate keys are derived for each direction using SHA-256:

```
C2S_key = SHA-256(ss_pq || ss_x25519 || U8(algId) || "QuantaVNC-PQKEM-C2S")
S2C_key = SHA-256(ss_pq || ss_x25519 || U8(algId) || "QuantaVNC-PQKEM-S2C")
```

Where:
- `ss_pq` is the ML-KEM shared secret (32 bytes)
- `ss_x25519` is the X25519 shared secret (32 bytes)
- `algId` is the negotiated algorithm ID (1 byte) -- this binds the algorithm choice to the key derivation, preventing downgrade attacks
- Direction labels ensure the client-to-server and server-to-client keys are distinct

Each key derivation produces a 256-bit key used for AES-256-EAX authenticated encryption of RFB protocol messages in the corresponding direction.

## PQTLS / PQX509 Security Types

The PQTLS and PQX509 security types use GnuTLS with post-quantum key exchange groups. Rather than implementing PQC within the RFB protocol, they configure TLS to use hybrid ML-KEM + ECDH key exchange groups, providing PQC protection through the standard TLS 1.3 handshake.

- **PQTLS**: Anonymous TLS with PQ groups (no certificate verification)
- **PQX509**: TLS with PQ groups and X.509 certificate verification

These types benefit from the maturity of TLS implementations while gaining post-quantum security.

## Comparison with Classical Security

| Property                  | RSA-2048 + AES-128       | QuantaVNC PQKEM             |
|---------------------------|--------------------------|------------------------------|
| Key exchange              | RSA or ECDH              | ML-KEM-768 + X25519 hybrid  |
| Symmetric cipher          | AES-128                  | AES-256-EAX                  |
| Quantum resistance        | None                     | NIST Level 3                 |
| Forward secrecy           | Only with ECDHE          | Always (ephemeral KEM)       |
| Handshake overhead        | ~0.5 KB                  | ~5 KB                        |
| Handshake latency         | ~1 ms                    | ~2 ms                        |

## Known Limitations

1. **ML-DSA server authentication**: Server identity is authenticated using ML-DSA (FIPS 204) digital signatures. The server generates a persistent ML-DSA signing keypair and signs each ephemeral key exchange. The client verifies the signature and uses TOFU (trust-on-first-use) fingerprinting of the ML-DSA public key.

2. **Java viewer does not support PQC**: The Java viewer does not implement PQC security types. When connecting to a PQC-enabled server, it will negotiate classical security types. If the server requires PQC (`PQCMode=required`), the Java viewer will not be able to connect.

3. **No quantum-safe password authentication**: VNC password authentication (DES-based challenge-response) and Plain authentication transmit credentials inside the encrypted channel. While the channel is quantum-safe, the underlying auth protocols are unchanged.

4. **Algorithm agility**: QuantaVNC supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024 with runtime algorithm negotiation. The server selects the strongest algorithm available in its liboqs installation and communicates this to the client during the handshake.

5. **Side-channel hardening**: QuantaVNC relies on liboqs for ML-KEM implementation. The constant-time properties of the implementation depend on the liboqs build configuration and the target platform.

6. **Increased bandwidth**: The hybrid key exchange adds approximately 4.5 KB to the initial handshake compared to classical key exchange. This is negligible for most connections but may be relevant for extremely constrained networks.

## Session Rekeying

### Forward Secrecy Model

Each PQKEM connection uses **ephemeral** ML-KEM and X25519 keys generated fresh for every connection. This provides forward secrecy: compromise of long-term credentials (ML-DSA signing key, VNC password) does not allow decryption of previously recorded sessions.

### Rekeying Strategy

QuantaVNC uses **connection-based rekeying** rather than in-band rekeying:

- The AES-256-EAX cipher uses a 128-bit counter (2^128 messages before wraparound — practically infinite)
- For time-based forward secrecy, the server supports a `PQCRekeyInterval` parameter that limits session duration
- When the interval expires, the server gracefully closes the connection
- The client automatically reconnects, triggering a fresh PQC key exchange with new ephemeral keys
- For PQTLS/PQX509 types, TLS 1.3's built-in KeyUpdate mechanism handles rekeying

This approach is recommended by NIST for protocols with ephemeral key exchange, as it avoids the complexity and potential vulnerabilities of in-band rekeying protocols.

### Configuration

```bash
# Limit sessions to 1 hour for forward secrecy (default: 0 = no limit)
vncserver -PQCRekeyInterval=3600
```
