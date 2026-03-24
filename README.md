<p align="center">
  <h1 align="center">QuantaVNC</h1>
  <p align="center">
    Post-Quantum Cryptography VNC Platform
    <br />
    <em>by <a href="https://github.com/dyber-pqc">Dyber, Inc.</a></em>
  </p>
</p>

<p align="center">
  <a href="https://github.com/dyber-pqc/QuantaVNC/actions/workflows/build.yml"><img src="https://github.com/dyber-pqc/QuantaVNC/actions/workflows/build.yml/badge.svg" alt="Build Status"></a>
  <a href="LICENCE.TXT"><img src="https://img.shields.io/badge/license-GPL--2.0-blue.svg" alt="License: GPL v2"></a>
  <a href="https://github.com/open-quantum-safe/liboqs"><img src="https://img.shields.io/badge/PQC-ML--KEM--768-green.svg" alt="PQC: ML-KEM-768"></a>
  <a href="https://csrc.nist.gov/projects/post-quantum-cryptography"><img src="https://img.shields.io/badge/NIST-FIPS%20203-orange.svg" alt="NIST FIPS 203"></a>
</p>

---

**QuantaVNC** is a post-quantum cryptography VNC platform based on [TigerVNC](https://github.com/TigerVNC/tigervnc). It protects remote desktop sessions against current and future cryptographic threats, including "harvest now, decrypt later" attacks by quantum computers.

## Why Post-Quantum?

Adversaries can record encrypted VNC sessions today and decrypt them once large-scale quantum computers become available. QuantaVNC addresses this by integrating **NIST-standardized post-quantum algorithms** into the VNC protocol:

- **ML-KEM** (FIPS 203) for quantum-resistant key encapsulation
- **Hybrid approach**: classical X25519 + post-quantum ML-KEM-768 -- if either algorithm holds, the session stays secure
- **AES-256-EAX** authenticated encryption for channel protection

## Architecture

```
┌───────────────┐                              ┌───────────────┐
│  VNC Client   │                              │  VNC Server   │
│               │                              │               │
│  ┌─────────┐  │   ML-KEM-768 + X25519        │  ┌─────────┐  │
│  │  liboqs │──│──────hybrid key exchange─────│──│  liboqs │  │
│  └─────────┘  │                              │  └─────────┘  │
│               │   AES-256-EAX encrypted      │               │
│  ┌─────────┐  │   ═══════════════════════    │  ┌─────────┐  │
│  │ Nettle  │──│── RFB protocol messages  ────│──│ Nettle  │  │
│  └─────────┘  │   ═══════════════════════    │  └─────────┘  │
│               │                              │               │
│  ┌─────────┐  │   TLS 1.3 + PQ groups        │  ┌──────────┐ │
│  │ GnuTLS  │──│──(PQTLS/PQX509 types)────────│──│ GnuTLS   │ │
│  └─────────┘  │                              │  └──────────┘ │
└───────────────┘                              └───────────────┘
```

QuantaVNC provides two PQC approaches:

1. **PQKEM** -- custom ML-KEM-768 + X25519 hybrid key exchange directly in the RFB protocol, with AES-256-EAX encryption. Fully implemented and functional.
2. **PQTLS/PQX509** -- TLS 1.3 with post-quantum key exchange groups via GnuTLS. Depends on GnuTLS PQ group support.

## Features

- **ML-KEM-768 + X25519** hybrid key exchange (PQKEM security types)
- **PQC-enhanced TLS** with ML-KEM groups (PQTLS / PQX509 security types)
- **TOFU server verification** -- fingerprint-based trust-on-first-use
- **Backward compatible** -- standard VNC clients connect using classical security
- **Cross-platform** -- Windows, Linux, macOS
- **Java viewer** with PQC negotiation
- **GUI configuration** -- "Require PQC" checkbox in viewer options

## Security Types

| Type | Auth | Key Exchange | Encryption |
|------|------|-------------|------------|
| `PQKEMNone` | None | ML-KEM-768 + X25519 | AES-256-EAX |
| `PQKEMVnc` | VNC password | ML-KEM-768 + X25519 | AES-256-EAX |
| `PQKEMPlain` | Username/password | ML-KEM-768 + X25519 | AES-256-EAX |
| `PQTLSNone` | None | TLS + ML-KEM groups | TLS 1.3 |
| `PQTLSVnc` | VNC password | TLS + ML-KEM groups | TLS 1.3 |
| `PQTLSPlain` | Username/password | TLS + ML-KEM groups | TLS 1.3 |
| `PQX509None` | X.509 cert | TLS + ML-KEM groups | TLS 1.3 |
| `PQX509Vnc` | X.509 + VNC | TLS + ML-KEM groups | TLS 1.3 |
| `PQX509Plain` | X.509 + user/pass | TLS + ML-KEM groups | TLS 1.3 |

All classical TigerVNC security types (None, VncAuth, TLSVnc, X509Plain, RA2, etc.) remain fully supported.

## Quick Start

### Build

```bash
# Install liboqs first -- see BUILDING.md for platform-specific instructions

mkdir build && cd build
cmake -DENABLE_PQC=ON -DENABLE_GNUTLS=ON -DENABLE_NETTLE=ON ..
make -j$(nproc)
```

### Dependencies

| Dependency | Minimum Version | Purpose |
|-----------|----------------|---------|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.9.0 | Post-quantum algorithms (ML-KEM-768) |
| [GnuTLS](https://www.gnutls.org/) | 3.6.0 | TLS / X.509 |
| [Nettle](https://www.lysator.liu.se/~nisse/nettle/) | 3.4 | AES-EAX, SHA-256, X25519 |
| [FLTK](https://www.fltk.org/) | 1.3.3 | GUI toolkit |
| CMake | 3.10 | Build system |
| zlib | -- | Compression |
| Pixman | -- | Pixel manipulation |

See **[BUILDING.md](BUILDING.md)** for detailed platform-specific build instructions.

### Run

**Server** -- offer PQC security types:
```bash
vncserver -SecurityTypes PQKEMVnc,TLSVnc,VncAuth
```

**Client** -- PQC types are preferred automatically when available:
```bash
vncviewer hostname:1
```

**Force PQC-only connections:**
```bash
vncviewer -PQCRequired=1 hostname:1
```

## Documentation

- [BUILDING.md](BUILDING.md) -- Build instructions for Linux, Windows, macOS
- [doc/PQC-SECURITY.md](doc/PQC-SECURITY.md) -- Security analysis, protocol details, threat model

## Security Considerations

QuantaVNC is designed to protect against harvest-now-decrypt-later attacks. Please review [doc/PQC-SECURITY.md](doc/PQC-SECURITY.md) for the full threat model and known limitations:

- Server authentication currently uses classical algorithms (ML-DSA signatures planned)
- VNC password auth transmits credentials inside the PQC-encrypted channel
- ML-KEM-768 is hardcoded; algorithm negotiation is planned for future versions
- Side-channel properties depend on the liboqs build configuration

> **Note**: QuantaVNC has not undergone a formal third-party security audit. Organizations with high-security requirements should evaluate accordingly.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/dyber-pqc/QuantaVNC).

All contributions must be compatible with the GNU General Public License v2.

## License

QuantaVNC is licensed under the **GNU General Public License v2** (or later). See [LICENCE.TXT](LICENCE.TXT).

**Copyright (C) 2026 Dyber, Inc.**

Based on TigerVNC -- Copyright (C) 2009-2026 TigerVNC Team and contributors.

<details>
<summary>Original copyright holders</summary>

```
Copyright (C) 1999 AT&T Laboratories Cambridge
Copyright (C) 2002-2005 RealVNC Ltd.
Copyright (C) 2000-2006 TightVNC Group
Copyright (C) 2005-2006 Martin Koegler
Copyright (C) 2005-2006 Sun Microsystems, Inc.
Copyright (C) 2006 OCCAM Financial Technology
Copyright (C) 2000-2008 Constantin Kaplinsky
Copyright (C) 2004-2017 Peter Astrand for Cendio AB
Copyright (C) 2010 Antoine Martin
Copyright (C) 2010 m-privacy GmbH
Copyright (C) 2009-2011 D. R. Commander
Copyright (C) 2009-2011 Pierre Ossman for Cendio AB
Copyright (C) 2004, 2009-2011 Red Hat, Inc.
Copyright (C) 2009-2026 TigerVNC Team
```

See individual source files for complete copyright and license details.

</details>

## Acknowledgements

- [TigerVNC](https://github.com/TigerVNC/tigervnc) -- the upstream project this fork is based on
- [Open Quantum Safe](https://openquantumsafe.org/) -- liboqs post-quantum cryptography library
- [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography) -- ML-KEM (FIPS 203) and ML-DSA (FIPS 204) standards
