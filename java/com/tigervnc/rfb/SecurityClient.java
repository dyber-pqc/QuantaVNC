/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright (C) 2010 TigerVNC Team
 * Copyright (C) 2011-2017 Brian P. Hinz
 * Copyright (C) 2026 Dyber, Inc. -- QuantaVNC PQC modifications
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

package com.tigervnc.rfb;

public class SecurityClient extends Security {

  public SecurityClient() { super(secTypes); }

  public CSecurity GetCSecurity(int secType)
  {
    assert (CSecurity.upg != null); /* (upg == null) means bug in the viewer */
    assert (CSecurityTLS.msg != null);

    if (!IsSupported(secType))
      throw new Exception("Security type not supported");

    switch (secType) {
    case Security.secTypeNone: return (new CSecurityNone());
    case Security.secTypeVncAuth: return (new CSecurityVncAuth());
    case Security.secTypeVeNCrypt: return (new CSecurityVeNCrypt(this));
    case Security.secTypePlain: return (new CSecurityPlain());
    case Security.secTypeIdent: return (new CSecurityIdent());
    case Security.secTypeTLSNone:
      return (new CSecurityStack(secTypeTLSNone, "TLS with no password",
  			      new CSecurityTLS(true), null));
    case Security.secTypeTLSVnc:
      return (new CSecurityStack(secTypeTLSVnc, "TLS with VNCAuth",
  			      new CSecurityTLS(true), new CSecurityVncAuth()));
    case Security.secTypeTLSPlain:
      return (new CSecurityStack(secTypeTLSPlain, "TLS with Username/Password",
  			      new CSecurityTLS(true), new CSecurityPlain()));
    case Security.secTypeTLSIdent:
      return (new CSecurityStack(secTypeTLSIdent, "TLS with username only",
  			      new CSecurityTLS(true), new CSecurityIdent()));
    case Security.secTypeX509None:
      return (new CSecurityStack(secTypeX509None, "X509 with no password",
  			      new CSecurityTLS(false), null));
    case Security.secTypeX509Vnc:
      return (new CSecurityStack(secTypeX509Vnc, "X509 with VNCAuth",
  			      new CSecurityTLS(false), new CSecurityVncAuth()));
    case Security.secTypeX509Plain:
      return (new CSecurityStack(secTypeX509Plain, "X509 with Username/Password",
  			      new CSecurityTLS(false), new CSecurityPlain()));
    case Security.secTypeX509Ident:
      return (new CSecurityStack(secTypeX509Ident, "X509 with username only",
  			      new CSecurityTLS(false), new CSecurityIdent()));
    case Security.secTypeRA2:
      return (new CSecurityRSAAES(secType, 128, true));
    case Security.secTypeRA2ne:
      return (new CSecurityRSAAES(secType, 128, false));
    case Security.secTypeRA256:
      return (new CSecurityRSAAES(secType, 256, true));
    case Security.secTypeRAne256:
      return (new CSecurityRSAAES(secType, 256, false));

    // QuantaVNC PQC-KEM types (ML-KEM + X25519 hybrid key exchange)
    case Security.secTypePQKEMNone:
      return (new CSecurityPQKEM(secTypePQKEMNone, true));
    case Security.secTypePQKEMVnc:
      return (new CSecurityPQKEM(secTypePQKEMVnc, true));
    case Security.secTypePQKEMPlain:
      return (new CSecurityPQKEM(secTypePQKEMPlain, true));

    // QuantaVNC PQC-TLS types (PQC + TLS stack)
    case Security.secTypePQTLSNone:
      return (new CSecurityStack(secTypePQTLSNone, "PQ-TLS with no password",
                  new CSecurityTLS(true), null));
    case Security.secTypePQTLSVnc:
      return (new CSecurityStack(secTypePQTLSVnc, "PQ-TLS with VNCAuth",
                  new CSecurityTLS(true), new CSecurityVncAuth()));
    case Security.secTypePQTLSPlain:
      return (new CSecurityStack(secTypePQTLSPlain, "PQ-TLS with Username/Password",
                  new CSecurityTLS(true), new CSecurityPlain()));

    // QuantaVNC PQC-X509 types (PQC + X509 stack)
    case Security.secTypePQX509None:
      return (new CSecurityStack(secTypePQX509None, "PQ-X509 with no password",
                  new CSecurityTLS(false), null));
    case Security.secTypePQX509Vnc:
      return (new CSecurityStack(secTypePQX509Vnc, "PQ-X509 with VNCAuth",
                  new CSecurityTLS(false), new CSecurityVncAuth()));
    case Security.secTypePQX509Plain:
      return (new CSecurityStack(secTypePQX509Plain, "PQ-X509 with Username/Password",
                  new CSecurityTLS(false), new CSecurityPlain()));

    default:
      throw new Exception("Security type not supported");
    }

  }

  public static void setDefaults()
  {
      CSecurityTLS.setDefaults();
  }

  public static StringParameter secTypes
  = new StringParameter("SecurityTypes",
                        "Specify which security scheme to use (PQKEMPlain, PQKEMVnc, PQKEMNone, PQTLSPlain, PQTLSVnc, PQTLSNone, PQX509Plain, PQX509Vnc, PQX509None, X509Ident, X509Plain, TLSIdent, TLSPlain, X509Vnc, TLSVnc, X509None, TLSNone, Ident, RA2_256, RA2, RA2ne_256, RA2ne, VncAuth, None)",
                        "PQKEMPlain,PQKEMVnc,PQKEMNone,PQTLSPlain,PQTLSVnc,PQTLSNone,PQX509Plain,PQX509Vnc,PQX509None,X509Ident,X509Plain,TLSIdent,TLSPlain,X509Vnc,TLSVnc,X509None,TLSNone,Ident,RA2_256,RA2,RA2ne_256,RA2ne,VncAuth,None", Configuration.ConfigurationObject.ConfViewer);

}
