// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * pppencap.hh -- element encapsulates packet in PPP header
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
 * $Id: pppencap.hh,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

/*
=c

PPPEncap(PROTOCOL, I<KEYWORDS>)

=s GRE, encapsulation

encapsulates packets in static PPP header

=d

Encapsulates each incoming packet in a PPP packet with protocol
PROTOCOL. Default protocol is 0x0021 (IPv4-in-PPP).

Keyword arguments are:

=over 8

=item ADDRESS

Byte. Sets the Address field to the specified value. Default is 0xff
(all stations).

=item CONTROL

Byte. Sets the Control field to the specified value. Default is 0x03
(unnumbered information).

=back

=e

Wraps packets in a PPP header specifying PPP protocol 0x0021
(IPv4-in-PPP):

  PPPEncap(0x0021)

Strpis PPP header:

  Strip(4)

=a Strip */

#ifndef CLICK_PPPENCAP_HH
#define CLICK_PPPENCAP_HH
#include <click/element.hh>
#include "ppp_defs.h"
CLICK_DECLS

class PPPEncap : public Element { public:

  PPPEncap() : Element(1, 1) {
    _ppp.address = PPP_ALLSTATIONS;
    _ppp.control = PPP_UI;
    _ppp.protocol = htons(PPP_IP);
    MOD_INC_USE_COUNT;
  }
  virtual ~PPPEncap() { MOD_DEC_USE_COUNT; }

  const char *class_name() const { return "PPPEncap"; }
  const char *processing() const { return AGNOSTIC; }
  PPPEncap *clone() const { return new PPPEncap; }

  int configure(Vector<String> &, ErrorHandler *);

  Packet * simple_action(Packet *);

private:

  struct ppp_header _ppp;

};

CLICK_ENDDECLS
#endif
