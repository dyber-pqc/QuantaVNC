/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
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
//
// secTypes.h - constants for the various security types.
//

#ifndef __RFB_SECURITYCLIENT_H__
#define __RFB_SECURITYCLIENT_H__

#include <rfb/Security.h>

namespace rfb {

  class CConnection;
  class CSecurity;

  class SecurityClient : public Security {
  public:
    SecurityClient(void) : Security(secTypes) {}

    /* Create client side CSecurity class instance */
    CSecurity* GetCSecurity(CConnection* cc, uint32_t secType);

    /* Override to apply PQCMode filtering */
    const std::list<uint32_t> GetEnabledExtSecTypes(void);

    /* Apply PQC mode filtering based on the pqcMode parameter */
    void applyPQCMode(const char* mode);

    static core::EnumListParameter secTypes;
  };

}

#endif
