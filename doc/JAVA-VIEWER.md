# Java Viewer PQC Limitations

## Current Status

The QuantaVNC Java viewer **does not support post-quantum cryptography (PQC) security types**. When connecting to a PQC-enabled server, the Java viewer will negotiate classical security types (TLS, X.509, VncAuth, etc.) via the standard VeNCrypt fallback mechanism.

## Behavior

| Server PQCMode | Java Viewer Behavior |
|----------------|---------------------|
| `preferred` (default) | Connects using classical security (TLS/VncAuth) |
| `required` | **Connection rejected** — server only offers PQC types |
| `off` | Connects normally using classical security |

## Why No PQC in Java?

The PQKEM protocol requires:
- **ML-KEM** (FIPS 203) key encapsulation via liboqs
- **ML-DSA** (FIPS 204) signature verification via liboqs
- **X25519** elliptic curve Diffie-Hellman
- **AES-256-EAX** authenticated encryption via Nettle

These are C libraries. The Java viewer would need either:
1. JNI bindings to liboqs/Nettle (complex, platform-specific)
2. Pure Java implementations via BouncyCastle (bcprov 1.78+ has ML-KEM)

Neither is implemented yet.

## Recommendation

For PQC-protected connections, use the **QuantaVNC native client** (available for Linux, Windows, macOS):

```bash
# Native client with PQC (recommended)
vncviewer -PQCMode=preferred hostname:1
```

## Future Plans

BouncyCastle 1.78+ includes `org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider` with ML-KEM support. A future version of the Java viewer may integrate this for PQC key exchange. This is tracked as a future enhancement.

## Server Configuration for Mixed Deployments

If you need to support both native PQC clients and Java viewers:

```bash
# Server offers PQC first, classical fallback for Java clients
vncserver -PQCMode=preferred -SecurityTypes PQKEMVnc,TLSVnc,VncAuth
```

This allows native clients to use PQC while Java clients fall back to TLS.
