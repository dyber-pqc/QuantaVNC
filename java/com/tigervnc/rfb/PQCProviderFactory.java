/* Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

package com.tigervnc.rfb;

/**
 * Factory to create the best available PQC provider.
 * Tries liboqs-java first (native, matches C++ client), then Bouncy Castle.
 */
public final class PQCProviderFactory {

  private static PQCProvider cached;
  private static boolean probed = false;

  private PQCProviderFactory() {}

  /**
   * Get the PQC provider, or null if none is available.
   */
  public static synchronized PQCProvider create() {
    if (probed) return cached;
    probed = true;

    // Try liboqs-java first (same native crypto as C++ client)
    try {
      if (LiboqsPQCProvider.isAvailable()) {
        cached = new LiboqsPQCProvider();
        LogWriter vlog = new LogWriter("PQCProviderFactory");
        vlog.info("PQC provider: liboqs-java (native)");
        return cached;
      }
    } catch (Throwable t) { /* not available */ }

    // Fall back to Bouncy Castle (pure Java)
    try {
      if (BCPQCProvider.isAvailable()) {
        cached = new BCPQCProvider();
        LogWriter vlog = new LogWriter("PQCProviderFactory");
        vlog.info("PQC provider: Bouncy Castle");
        return cached;
      }
    } catch (Throwable t) { /* not available */ }

    return null;
  }

  /**
   * Check if any PQC provider is available.
   */
  public static boolean isAvailable() {
    return create() != null;
  }
}
