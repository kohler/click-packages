// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * ipcp.cc -- PPP IP Control Protocol
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
 * $Id: ipcp.cc,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/packet.hh>

#include "ppp_defs.h"
#include "pppcontrolprotocol.hh"
#include "ipcp.hh"

CLICK_DECLS

int
IPCP::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_parse(conf, this, errh,
                  cpIPAddress, "local IP address", &_localip,
                  cpIPAddress, "remote IP address", &_remoteip,
                  cpKeywords,
		  "VERBOSE", cpBool, "verbose", &_verbose,
                  cpEnd) < 0)
    return -1;

  return 0;
}

unsigned
IPCP::addci(uint8_t *data)
{
  struct ppp_ci *ci;

  ci = (struct ppp_ci *)data;
  ci->type = CI_ADDR;
  ci->len = offsetof(struct ppp_ci, data) + sizeof(_localip.addr());
  memcpy(ci->data, _localip.data(), sizeof(_localip.addr()));

  return (unsigned)ci->len;
}

void
IPCP::reqci(WritablePacket *p)
{
  struct ppp_header *ppp = (struct ppp_header *)p->data();
  struct ppp_cp *cp = (struct ppp_cp *)&ppp[1];
  struct ppp_ci *ci, *next;

  // reject by default
  cp->code = CONFREJ;

  ci = (struct ppp_ci *)&cp->data;
  while ((unsigned char *)&ci->len < p->end_data()) {
    next = (struct ppp_ci *)((unsigned)ci + ci->len);
    // runt or bad length field
    if ((unsigned char *)next > p->end_data()) {
      cp->code = CONFREJ;
      // bail
      return;
    }
    // only deal with IP address
    if (ci->type != CI_ADDR ||
	ci->len != (offsetof(struct ppp_ci, data) + sizeof(_remoteip.addr()))) {
      cp->code = CONFREJ;
      break;
    }
    // nak if different
    if (memcmp(ci->data, _remoteip.data(), sizeof(_remoteip.addr())))
      cp->code = CONFNAK;
    else
      cp->code = cp->code != CONFNAK ? CONFACK : CONFNAK;
    ci = next;
  }

  ci = (struct ppp_ci *)&cp->data;
  while ((unsigned char *)&ci->len < p->end_data()) {
    next = (struct ppp_ci *)((unsigned)ci + ci->len);
    // runt or bad length field
    if ((unsigned char *)next > p->end_data()) {
      // bail
      return;
    }
    if (ci->type == CI_ADDR) {
      if (cp->code == CONFREJ) {
	// filter IP address from reject
	cp->len = htons(ntohs(cp->len) - ci->len);
	memmove(ci, next, p->end_data() - (unsigned char *)next);
	p->take((unsigned)next - (unsigned)ci);
	next = (struct ppp_ci *)((unsigned)ci + ci->len);
      }
      else {
	// fill with his address
	memcpy(ci->data, _remoteip.data(), sizeof(_remoteip.addr()));
      }
    }
    ci = next;
  }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(PPPControlProtocol)
EXPORT_ELEMENT(IPCP)
