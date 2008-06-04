// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * lcp.cc -- PPP Link Control Protocol
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
 * $Id: lcp.cc,v 1.2 2005/09/19 22:45:07 eddietwo Exp $
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/packet.hh>

#include "ppp_defs.h"
#include "pppcontrolprotocol.hh"
#include "lcp.hh"

CLICK_DECLS

unsigned
LCP::addci(uint8_t *data)
{
  struct ppp_ci *ci;

  ci = (struct ppp_ci *)data;
  ci->type = CI_MAGICNUMBER;
  ci->len = offsetof(struct ppp_ci, data) + sizeof(magic);
  // recalculate magic number
  if (state != REQSENT && state != ACKRCVD && state != ACKSENT)
    magic = click_random();
  memcpy(ci->data, &magic, sizeof(magic));

  return (unsigned)ci->len;
}

void
LCP::reqci(WritablePacket *p)
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
    // only deal with magic number
    if (ci->type != CI_MAGICNUMBER) {
      cp->code = CONFREJ;
      break;
    }
    cp->code = CONFACK;
    ci = next;
  }

  if (cp->code == CONFREJ) {
    // filter magic number from reject
    ci = (struct ppp_ci *)&cp->data;
    while ((unsigned char *)&ci->len < p->end_data()) {
      next = (struct ppp_ci *)((unsigned)ci + ci->len);
      // runt or bad length field
      if ((unsigned char *)next > p->end_data()) {
	// bail
	return;
      }
      if (ci->type == CI_MAGICNUMBER) {
	cp->len = htons(ntohs(cp->len) - ci->len);
	memmove(ci, next, p->end_data() - (unsigned char *)next);
	p->take((unsigned)next - (unsigned)ci);
	next = (struct ppp_ci *)((unsigned)ci + ci->len);
      }
      ci = next;
    }
  }
}

void
LCP::protreject(WritablePacket *p)
{
  // protocol reject data
  p->pull(offsetof(struct ppp_header, protocol));
  sdata(PROTREJ, ++id, p->data(), p->length());

  if (_verbose)
    click_chatter("%s: rejected protocol 0x%04x", declaration().c_str(), *(uint16_t *)p->data());
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(PPPControlProtocol)
EXPORT_ELEMENT(LCP)
