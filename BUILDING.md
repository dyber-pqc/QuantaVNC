# Building QuantaVNC

## Prerequisites

### All Platforms

- CMake 3.10 or later
- A C/C++ compiler with C99 and C++11 support (GCC, Clang, or MinGW)
- zlib
- Pixman

### PQC Support

- **liboqs >= 0.9.0** (Open Quantum Safe library)

### TLS and Authentication

- GnuTLS >= 3.6.0
- Nettle

### GUI (Viewer)

- FLTK 1.3.3 or later

### Linux Additional

- X11 development libraries (Xdamage, Xfixes, Xrandr, Xtest)
- PAM development libraries
- gettext (optional, for translations)

### Java Viewer

- Java JDK 11 or later
- BouncyCastle (for PQC support in the Java viewer)

## Installing liboqs

### Linux (Debian/Ubuntu)

**Option A: Build from source (recommended)**

```bash
sudo apt install cmake gcc ninja-build libssl-dev
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig
```

**Option B: From package manager (if available)**

```bash
# Check your distribution's repositories
sudo apt install liboqs-dev
```

### Windows (MSYS2/MinGW)

```bash
# From an MSYS2 MinGW64 shell:
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/mingw64 ..
ninja
ninja install
```

Alternatively, if using vcpkg:

```bash
vcpkg install liboqs:x64-mingw-static
```

### macOS (Homebrew)

```bash
brew install cmake ninja openssl

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
```

## CMake Configuration Options

| Option          | Default | Description                                           |
|-----------------|---------|-------------------------------------------------------|
| `ENABLE_PQC`    | AUTO    | Post-quantum cryptography support (requires liboqs)   |
| `ENABLE_GNUTLS` | AUTO    | Protocol encryption and advanced authentication       |
| `ENABLE_NETTLE` | AUTO    | RSA-AES security types                                |
| `ENABLE_NLS`    | AUTO    | Translation of program messages (requires gettext)    |
| `BUILD_WINVNC`  | ON      | Build the Windows VNC server                          |
| `ENABLE_ASAN`   | OFF     | Address sanitizer (debug builds, Linux only)          |
| `ENABLE_TSAN`   | OFF     | Thread sanitizer (debug builds, Linux 64-bit only)    |

Set options to `ON` to require them (build fails if dependency is missing), `OFF` to disable, or `AUTO` (default) to enable if the dependency is found.

## Build Steps

### Linux

```bash
# Install system dependencies (Debian/Ubuntu)
sudo apt install cmake g++ libgnutls28-dev libfltk1.3-dev \
    libpixman-1-dev zlib1g-dev libpam0g-dev libx11-dev \
    libxdamage-dev libxfixes-dev libxrandr-dev libxtst-dev \
    nettle-dev gettext

# Build QuantaVNC
cd tigervnc-master
mkdir build && cd build
cmake -DENABLE_PQC=ON ..
make -j$(nproc)
sudo make install
```

### Windows (MSYS2/MinGW)

```bash
# Install dependencies in MSYS2 MinGW64 shell
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-gnutls mingw-w64-x86_64-fltk \
    mingw-w64-x86_64-pixman mingw-w64-x86_64-nettle \
    mingw-w64-x86_64-zlib

# Build
cd tigervnc-master
mkdir build && cd build
cmake -G"MinGW Makefiles" -DENABLE_PQC=ON ..
mingw32-make -j$(nproc)
```

### macOS

```bash
brew install cmake gnutls fltk pixman nettle

cd tigervnc-master
mkdir build && cd build
cmake -DENABLE_PQC=ON ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

## Verifying PQC Support

During CMake configuration, check the output for:

```
-- Found LibOQS: /usr/local/lib/liboqs.so (found version "0.9.0")
```

If PQC is enabled successfully, you will also see:

```
-- Post-Quantum Cryptography support enabled
```

If liboqs is not found and `ENABLE_PQC` is set to `AUTO`, PQC support is silently disabled. Set `ENABLE_PQC=ON` to make it a hard requirement:

```bash
cmake -DENABLE_PQC=ON ..
```

This will produce a clear error if liboqs is not installed.

## Troubleshooting

**CMake cannot find liboqs**: If you installed liboqs to a non-standard location, point CMake to it:

```bash
cmake -DCMAKE_PREFIX_PATH=/path/to/liboqs/install ..
```

**MSVC is not supported**: QuantaVNC must be built with GCC or Clang. On Windows, use MSYS2/MinGW.

**Missing X11 libraries on Linux**: Install the full X11 development package:

```bash
sudo apt install xorg-dev
```
