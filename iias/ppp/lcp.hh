// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * lcp.hh -- PPP Link Control Protocol
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
 * $Id: lcp.hh,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

/*
=c

LCP([I<KEYWORDS>])

=s PPP

PPP Link Control Protocol (LCP) Element.

=d

Expects PPP packets as input. Packets not of protocol type 0xc021
(PPP_LCP) are answered with an LCP Protocol Rejection. Outputs
PPP_LCP packets as required, which should be routed to the peer from
which the input packets were received.

Keyword arguments are:

=over 8

=item VERBOSE

Boolean. When true, LCP will print messages whenever it receives a
packet. Default is false.

=back

=a PPPControlProtocol, IPCP */

#ifndef CLICK_LCP_HH
#define CLICK_LCP_HH
#include <click/element.hh>
#include <click/timer.hh>
#include "ppp_defs.h"
#include "pppcontrolprotocol.hh"
CLICK_DECLS

class LCP : public PPPControlProtocol { public:

  LCP() : PPPControlProtocol(PPP_LCP), magic(0) { MOD_INC_USE_COUNT; }
  ~LCP() { MOD_DEC_USE_COUNT; }

  const char *class_name() const { return "LCP"; }
  LCP *clone() const { return new LCP; }

protected:

  unsigned addci(uint8_t *);
  void reqci(WritablePacket *);
  void protreject(WritablePacket *);

private:

  uint32_t magic;

};

CLICK_ENDDECLS
#endif
