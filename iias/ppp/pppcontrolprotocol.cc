// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * pppcontrolprotocol.cc -- virtual class for PPP control protocols
 * Mark Huang <mlhuang@cs.princeton.edu>
 *
 * Copyright (c) 2004  The Trustees of Princeton University (Trustees).
 *
 * Portions of this file are derived from fsm.c in the pppd package,
 * which has the following copyright.
 * 
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: pppcontrolprotocol.cc,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/packet.hh>

#include "ppp_defs.h"
#include "pppcontrolprotocol.hh"

CLICK_DECLS

int
PPPControlProtocol::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_parse(conf, this, errh,
                  cpKeywords,
		  "VERBOSE", cpBool, "verbose", &_verbose,
                  cpEnd) < 0)
    return -1;

  return 0;
}

int
PPPControlProtocol::initialize(ErrorHandler *)
{
  timer = new Timer(timeout, this);
  assert(timer);
  timer->initialize(this);

  return 0;
}

void
PPPControlProtocol::cleanup(CleanupStage)
{
  if (timer) {
    timer->unschedule();
    timer->cleanup();
    delete timer;
    timer = NULL;
  }
}

void
PPPControlProtocol::sdata(uint8_t code, uint8_t id, uint8_t *data, unsigned len)
{
  WritablePacket *p;
  struct ppp_header *ppp;
  struct ppp_cp *cp;

  // make up the request packet
  p = Packet::make(sizeof(struct ppp_header) + offsetof(struct ppp_cp, data) + len);
  assert(p);

  ppp = (struct ppp_header *)p->data();
  cp = (struct ppp_cp *)&ppp[1];

  ppp->address = PPP_ALLSTATIONS;
  ppp->control = PPP_UI;
  ppp->protocol = htons(protocol);

  cp->code = code;
  cp->id = id;
  cp->len = htons(offsetof(struct ppp_cp, data) + len);
  if (data)
    memcpy(cp->data, data, len);

  output(0).push(p);
}

void
PPPControlProtocol::sconfreq(bool retransmit)
{
  uint8_t data[PACKET_MAX];

  if (!retransmit) {
    retransmits = maxconfreqtransmits;
    reqid = ++id;
  }

  seen_ack = 0;

  // send the request to our peer
  sdata(CONFREQ, reqid, data, addci(data));

  // start the retransmit timer
  --retransmits;
  timer->schedule_after_s(timeouttime);

  if (_verbose)
    click_chatter("%s: sent Configuration Request %d", declaration().cc(), reqid);
}

Packet *
PPPControlProtocol::rconfreq(WritablePacket *p)
{
  struct ppp_header *ppp = (struct ppp_header *)p->data();
  struct ppp_cp *cp = (struct ppp_cp *)&ppp[1];

  if (_verbose)
    click_chatter("%s: received Configuration Request %d", declaration().cc(), cp->id);

  switch (state) {
  case OPENED:
  case STOPPED:
    // (re)start negotiation
    sconfreq(false);
    state = REQSENT;
    break;
  }

  reqci(p);

  if (cp->code == CONFACK) {
    if (state == ACKRCVD) {
      // done
      timer->unschedule();
      state = OPENED;
    }
    else {
      // leave timer running until we receive CONFACK
      state = ACKSENT;
      assert(timer->scheduled());
    }
    if (_verbose)
      click_chatter("%s: sent Configuration Ack %d", declaration().cc(), cp->id);
  }
  else {
    // revert from ACKSENT to REQSENT since we are rejecting
    if (state != ACKRCVD) {
      state = REQSENT;
      assert(timer->scheduled());
    }
    if (_verbose)
      click_chatter("%s: sent Configuration %s %d", declaration().cc(), cp->code == CONFREJ ? "Reject" : "Nak", cp->id);
  }

  return p;
}    

void
PPPControlProtocol::timeout(Timer *t, void *thunk)
{
  PPPControlProtocol *pppcp = (PPPControlProtocol *)thunk;

  switch (pppcp->state) {
  case STOPPING:
    if (pppcp->retransmits <= 0)
      pppcp->state = STOPPED;
    else {
      // retransmit
      pppcp->sdata(TERMREQ, pppcp->reqid = ++pppcp->id, NULL, 0);
      t->schedule_after_s(pppcp->timeouttime);
      --pppcp->retransmits;
    }
    break;

  case REQSENT:
  case ACKRCVD:
  case ACKSENT:
    if (pppcp->retransmits <= 0) {
      click_chatter("%s: timeout sending Configuration Requests", pppcp->declaration().cc());
      pppcp->state = STOPPED;
    }
    else {
      // retransmit
      click_chatter("%s: resending Configuration Request %d", pppcp->declaration().cc(), pppcp->reqid);
      pppcp->sconfreq(true);
      // leave timer running until we receive CONFACK before timeout
      if (pppcp->state == ACKRCVD) {
	pppcp->state = REQSENT;
	assert(t->scheduled());
      }
    }
    break;
  }
}

void
PPPControlProtocol::rconfack(WritablePacket *p)
{
  struct ppp_header *ppp = (struct ppp_header *)p->data();
  struct ppp_cp *cp = (struct ppp_cp *)&ppp[1];

  if (_verbose)
    click_chatter("%s: received Configuration Ack %d", declaration().cc(), cp->id);

  if (cp->id != reqid || seen_ack) {
    click_chatter("%s: bad Configuration Ack ID %d (expected %d)", declaration().cc(), cp->id, reqid);
    return;
  }

  seen_ack = 1;

  switch (state) {
  case STOPPED:
    sdata(TERMACK, cp->id, NULL, 0);
    break;
  case REQSENT:
    // leave timer running until we send CONFACK
    state = ACKRCVD;
    retransmits = maxconfreqtransmits;
    assert(timer->scheduled());
    break;
  case ACKSENT:
    // done
    timer->unschedule();
    state = OPENED;
    retransmits = maxconfreqtransmits;
    break;
  case ACKRCVD:
  case OPENED:
    // restart negotiation
    timer->unschedule();
    sconfreq(false);
    state = REQSENT;
    break;
  }
}

void
PPPControlProtocol::rconfnakrej(WritablePacket *p)
{
  struct ppp_header *ppp = (struct ppp_header *)p->data();
  struct ppp_cp *cp = (struct ppp_cp *)&ppp[1];

  if (_verbose)
    click_chatter("%s: received Configuration Nak/Reject %d", declaration().cc(), cp->id);

  if (cp->id != reqid || seen_ack) {
    click_chatter("%s: bad Configuration Nak/Reject ID %d (expected %d)", declaration().cc(), cp->id, reqid);
    return;
  }

  seen_ack = 1;

  switch (state) {
  case STOPPED:
    sdata(TERMACK, cp->id, NULL, 0);
    break;
  case REQSENT:
  case ACKSENT:
    // try again
    timer->unschedule();
    sconfreq(false);
    break;
  case ACKRCVD:
  case OPENED:
    // restart negotiation
    timer->unschedule();
    sconfreq(false);
    state = REQSENT;
    break;
  }
}

void
PPPControlProtocol::rtermreq(WritablePacket *p)
{
  struct ppp_header *ppp = (struct ppp_header *)p->data();
  struct ppp_cp *cp = (struct ppp_cp *)&ppp[1];

  if (_verbose)
    click_chatter("%s: received Termination Request %d", declaration().cc(), cp->id);

  switch (state) {
  case ACKRCVD:
  case ACKSENT:
    // start over but keep trying
    state = REQSENT;
    break;
  case OPENED:
    // restart negotiation
    retransmits = 0;
    state = STOPPING;
    timer->schedule_after_s(timeouttime);
    break;
  }

  sdata(TERMACK, cp->id, NULL, 0);
}

void
PPPControlProtocol::rtermack(WritablePacket *)
{
  if (_verbose)
    click_chatter("%s: received Termination Ack", declaration().cc());

  switch (state) {
  case STOPPING:
    timer->unschedule();
    state = STOPPED;
    break;
  case ACKRCVD:
    state = REQSENT;
    break;
  case OPENED:
    // restart negotiation
    sconfreq(false);
    state = REQSENT;
    break;
  }
}

Packet *
PPPControlProtocol::simple_action(Packet *p_in)
{
  WritablePacket *p = (WritablePacket *)p_in;
  struct ppp_header *ppp = (struct ppp_header *)p->data();
  struct ppp_cp *cp = (struct ppp_cp *)&ppp[1];

  // runt
  if (p->length() < sizeof(struct ppp_header)) {
    click_chatter("%s: runt packet", declaration().cc());
    goto done;
  }

  // deal with known protocol types
  if (ntohs(ppp->protocol) != protocol) {
    protreject(p);
    goto done;
  }

  // runt or bad length field
  if ((unsigned char *)&cp->len >= p->end_data() ||
      (unsigned char *)((unsigned)cp + ntohs(cp->len)) > p->end_data()) {
    click_chatter("%s: runt packet or bad length", declaration().cc());
    goto done;
  }

  // deal with known codes
  switch (cp->code) {
  case CONFREQ:
    return rconfreq(p);
  case CONFACK:
    rconfack(p);
    break;
  case CONFNAK:
  case CONFREJ:
    rconfnakrej(p);
    break;
  case TERMREQ:
    rtermreq(p);
    break;
  case TERMACK:
    rtermack(p);
    break;
  case CODEREJ:
    click_chatter("%s: Code Reject", declaration().cc());
    if (state == ACKRCVD)
      state = REQSENT;
    break;
  default:
    click_chatter("%s: unhandled code %d", declaration().cc(), cp->code);
    break;
  }

 done:
  p->kill();
  return NULL;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PPPControlProtocol)
