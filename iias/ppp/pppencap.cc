// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * pppencap.cc -- element encapsulates packet in PPP header
 * Mark Huang <mlhuang@cs.princeton.edu>
 *
 * Copyright (c) 2004  The Trustees of Princeton University (Trustees).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 *
 * $Id: pppencap.cc,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>

#include "ppp_defs.h"
#include "pppencap.hh"

CLICK_DECLS

int
PPPEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
  uint16_t protocol;

  if (cp_va_parse(conf, this, errh,
		  cpOptional,
                  cpShort, "protocol", &protocol,
                  cpKeywords,
		  "ADDRESS", cpByte, "address", &_ppp.address,
		  "CONTROL", cpByte, "control", &_ppp.control,
                  cpEnd) < 0)
    return -1;

  _ppp.protocol = htons(protocol);

  return 0;
}

Packet *
PPPEncap::simple_action(Packet *p_in)
{
  WritablePacket *p = p_in->push(sizeof(struct ppp_header));
  if (!p) return 0;

  struct ppp_header *ppp = reinterpret_cast<struct ppp_header *>(p->data());

  memcpy(ppp, &_ppp, sizeof(struct ppp_header));

  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PPPEncap)
ELEMENT_MT_SAFE(PPPEncap)
