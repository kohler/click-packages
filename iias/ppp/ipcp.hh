// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * ipcp.hh -- PPP IP Control Protocol
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
 * $Id: ipcp.hh,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

/*
=c

IPCP([I<KEYWORDS>])

=s PPP

PPP IP Control Protocol (IPCP) Element.

=d

Expects PPP packets as input. Packets not of protocol type 0x8021
(PPP_IPCP) are silently discarded. Outputs PPP_IPCP packets as
required, which should be routed to the peer from which the input
packets were received.

Keyword arguments are:

=over 8

=item VERBOSE

Boolean. When true, IPCP will print messages whenever it receives a
packet. Default is false.

=back

=a PPPControlProtocol, LCP */

#ifndef CLICK_IPCP_HH
#define CLICK_IPCP_HH
#include <click/element.hh>
#include <click/timer.hh>
#include "ppp_defs.h"
#include "pppcontrolprotocol.hh"
CLICK_DECLS

class IPCP : public PPPControlProtocol { public:

  IPCP() : PPPControlProtocol(PPP_IPCP), _localip(0), _remoteip(0) { MOD_INC_USE_COUNT; }
  ~IPCP() { MOD_DEC_USE_COUNT; }

  const char *class_name() const { return "IPCP"; }
  IPCP *clone() const { return new IPCP; }

  int configure(Vector<String> &, ErrorHandler *);

protected:

  unsigned addci(uint8_t *);
  void reqci(WritablePacket *);

private:

  IPAddress _localip, _remoteip;

};

CLICK_ENDDECLS
#endif
