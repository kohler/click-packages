// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * pppcontrolprotocol.hh -- virtual class for PPP control protocols
 * Mark Huang <mlhuang@cs.princeton.edu>
 *
 * Copyright (c) 2004  The Trustees of Princeton University (Trustees).
 *
 * Portions of this file are derived from fsm.h in the pppd package,
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
 * $Id: pppcontrolprotocol.hh,v 1.3 2005/02/07 21:20:56 eddietwo Exp $
 */

/*
=c

PPPControlProtocol([I<KEYWORDS>])

=s PPP

virtual class for PPP control protocols

=d

Not a real Element. Provides finite state machine (FSM) and basic
structure for derived PPP control protocol Elements (LCP, IPCP, etc.).

Keyword arguments are:

=over 8

=item VERBOSE

Boolean. When true, PPPControlProtocol will print messages whenever it
receives a packet. Default is false.

=back

=a LCP, IPCP */

#ifndef CLICK_PPPCONTROLPROTOCOL_HH
#define CLICK_PPPCONTROLPROTOCOL_HH
#include <click/element.hh>
#include <click/timer.hh>
#include "ppp_defs.h"
CLICK_DECLS

class PPPControlProtocol : public Element { public:

  PPPControlProtocol(int protocol = 0) :
    Element(1, 1),
    protocol(protocol),
    state(STOPPED),
    id(0), reqid(0), seen_ack(0),
    timeouttime(DEFTIMEOUT),
    maxconfreqtransmits(DEFMAXCONFREQS),
    retransmits(DEFMAXCONFREQS),
    _verbose(false),
    timer(NULL) { }
  virtual ~PPPControlProtocol() { }

  const char *class_name() const { return "PPPControlProtocol"; }
  const char *processing() const { return AGNOSTIC; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);

  Packet * simple_action(Packet *);

  // virtual functions implemented by derived protocols
  virtual unsigned addci(uint8_t *) { return 0; }
  virtual void reqci(WritablePacket *) { }
  virtual void protreject(WritablePacket *) { }

 protected:

  void sdata(uint8_t code, uint8_t id, uint8_t *data, unsigned len);

  int protocol;			/* Data Link Layer Protocol field value */
  int state;			/* State */
  u_char id;			/* Current id */
  u_char reqid;			/* Current request id */
  u_char seen_ack;		/* Have received valid Ack/Nak/Rej to Req */
  int timeouttime;		/* Timeout time in milliseconds */
  int maxconfreqtransmits;	/* Maximum Configure-Request transmissions */
  int retransmits;		/* Number of retransmissions left */

  bool _verbose;		// be verbose
  Timer *timer;			// timeout timer

private:

  void sconfreq(bool retransmit);
  static void timeout(Timer *, void *);
  Packet * rconfreq(WritablePacket *p);
  void rconfack(WritablePacket *p);
  void rconfnakrej(WritablePacket *p);
  void rtermreq(WritablePacket *p);
  void rtermack(WritablePacket *p);

};

CLICK_ENDDECLS
#endif
