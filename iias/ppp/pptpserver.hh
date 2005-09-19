// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * pptpserver.hh -- element handles PPTP connections
 * Mark Huang <mlhuang@cs.princeton.edu>
 *
 * Copyright (c) 2004  The Trustees of Princeton University (Trustees).
 *
 * Portions of this file are derived from the Poptop PPTP Server,
 * which has the following copyright.
 *
 * Copyright © 1999 Matthew Ramsay and others.
 *
 * Poptop is free software; you can redistribute it and/or modify it under
 * the  terms  of  the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your  option)  any  later
 * version.
 *
 * Poptop  is  distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY  or
 * FITNESS  FOR  A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with  Poptop; see the file COPYING.  If not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: pptpserver.hh,v 1.3 2005/09/19 22:45:09 eddietwo Exp $
 */

#ifndef CLICK_PPTPSERVER_HH
#define CLICK_PPTPSERVER_HH
#include <click/element.hh>
#include <click/timer.hh>
#include "ppp_defs.h"
CLICK_DECLS

/*
=title PPTPServer.u

=c

PPTPServer([I<KEYWORDS>])

=s devices

Handles PPTP-over-TCP connections.

=d

Handles PPTP-over-TCP connections. The number of tunnels supported is
equal to the number of input/output pairs.

PPPControlProtocol elements such as IPCP and LCP should feedback from
the outputs of PPTPServer to its inputs. IP packets destined for
remote peers should be PPP encapsulated (see PPPEncap) and routed to
the appropriate input. IP packets from the remote peer are pushed out
the appropriate output and should be PPP decapsulated (see Strip).

Keyword arguments are:

=over 8

=item VERBOSE

Boolean. When true, PPTPServer will print messages whenever it accepts a
new connection or drops an old one. Default is false.

=back

=e

The following snippet enables a single PPTP tunnel with local address
10.0.0.1 and remote address 10.0.0.100.

// Shared IP input path and routing table
ip :: CheckIPHeader(INTERFACES 10.0.0.1)
rt :: StaticIPLookup(
	10.0.0.1	0,
	10.0.0.100	1
)

// PPTP server
pptpd :: PPTPServer(VERBOSE 1)

// ppp0
pptpd[0]
	-> ppp0 :: Classifier(2/0021, 2/8021, -)

// IP from remote peer 0
ppp0[0]
	-> Strip(4)
	-> ip
	-> rt

// IPCP negotiation for peer 0
ppp0[1]
	-> IPCP(local, remote0, VERBOSE 1)
	-> [0]pptpd

// LCP negotiation for peer 0
ppp0[2]
	-> LCP(VERBOSE 1)
	-> [0]pptpd

// Local delivery
rt[0]
	-> Print(toh)
	-> Discard

// IP to remote peer 0
rt[1]
	-> PPPEncap(0x0021)
	-> [0]pptpd

=a PPPControlProtocol, IPCP, LCP, PPPEncap, Strip */

class PPTPServer : public Element { public:

  PPTPServer();
  ~PPTPServer();

  const char *class_name() const	{ return "PPTPServer"; }
  const char *port_count() const	{ return "-/-"; }
  const char *processing() const	{ return PUSH; }
  const char *flow_code() const		{ return "x/y"; }

  int configure(Vector<String> &conf, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);

  void selected(int);

 private:

  // PPTP or GRE connection
  struct Connection {
    void *ps;			// back pointer
    int fd;			// socket descriptor
    int input;			// input number
    WritablePacket *next;	// pending packet
    // PPTP connection state
    struct Connection *gre;	// associated GRE connection (PPTP only)
    // GRE connection state
    struct Connection *pptp;	// associated PPTP connection (GRE only)
    uint32_t seq_sent;		// last sequence number sent
    uint32_t seq_recv;		// last sequence number received
    uint32_t ack_sent;		// last acknowledgement number sent
    uint32_t ack_recv;		// last acknowledgement number received
    Timer *ack_timer;		// delayed acknowledgement timer
    Connection(int fd) : 
      ps(this), fd(fd),
      next(NULL), gre(NULL), pptp(NULL),
      seq_sent(0), seq_recv(0), ack_sent(0), ack_recv(0) { }
    ~Connection() { }
  };

  bool _verbose;		// be verbose
  int _fd;			// listen socket descriptor

  // hashed by socket descriptor
  Vector<Connection *> _connections;
  // hashed by input number
  Vector<Connection *> _inputs;

  // connection management
  int initialize_socket_error(ErrorHandler *, const char *);
  void cleanup_connection(struct Connection *c);
  Connection * initialize_pptp(int listen_fd);
  Connection * initialize_gre(int pptp_fd);

  // GRE output
  void push(int input, Packet *p);
  int send_gre(Connection *c, WritablePacket *p);
  static void send_ack(Timer *t, void *thunk);

  // GRE/PPP input
  void * handle_gre(Connection *c);

  // PPTP input
  void * handle_pptp(Connection *c);
};

#define IS_GRE(c) ((c)->pptp != NULL)
#define IS_PPTP(c) ((c)->pptp == NULL)

CLICK_ENDDECLS
#endif
