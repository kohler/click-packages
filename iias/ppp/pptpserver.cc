// -*- mode: c++; c-basic-offset: 2 -*-
/*
 * pptpserver.{cc,hh} -- element handles PPTP connections
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
 * $Id: pptpserver.cc,v 1.1 2004/04/17 14:51:14 mhuang Exp $
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/glue.hh>
#include <click/packet.hh>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "pptpdefs.h"
#include "pptpserver.hh"

CLICK_DECLS

PPTPServer::PPTPServer()
  : Element(1, 1), _verbose(false), _fd(-1)
{
  MOD_INC_USE_COUNT;
}

PPTPServer::~PPTPServer()
{
  MOD_DEC_USE_COUNT;
}

void
PPTPServer::notify_ninputs(int n)
{
  set_ninputs(n);
}

void
PPTPServer::notify_noutputs(int n)
{
  set_noutputs(n);
}

int
PPTPServer::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_parse(conf, this, errh,
                  cpKeywords,
		  "VERBOSE", cpBool, "verbose", &_verbose,
                  cpEnd) < 0)
    return -1;

  // seed PRNG
  click_random_srandom();

  return 0;
}

int
PPTPServer::initialize_socket_error(ErrorHandler *errh, const char *syscall)
{
  int e = errno;		// preserve errno

  if (_fd >= 0) {
    close(_fd);
    _fd = -1;
  }

  return errh->error("%s: %s", syscall, strerror(e));
}

int
PPTPServer::initialize(ErrorHandler *errh)
{
  struct sockaddr_in sin;

  for (int i = 0; i < ninputs(); i++)
    _inputs.push_back(NULL);

  // open socket, set options, bind to address
  _fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (_fd < 0)
    return initialize_socket_error(errh, "socket");

  sin.sin_family = PF_INET;
  sin.sin_port = htons(PPTP_PORT);
  sin.sin_addr = inet_makeaddr(0, 0);

  // bind to port
  if (bind(_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    return initialize_socket_error(errh, "bind");

  // start listening
  if (listen(_fd, 2) < 0)
    return initialize_socket_error(errh, "listen");

  // nonblocking I/O and close-on-exec for the socket
  fcntl(_fd, F_SETFL, O_NONBLOCK);
  fcntl(_fd, F_SETFD, FD_CLOEXEC);

  add_select(_fd, SELECT_READ);
  return 0;
}

void
PPTPServer::cleanup_connection(Connection *c)
{
  int fd = c->fd;

  // close socket and remove from select list
  if (fd >= 0) {
    close(fd);
    remove_select(fd, SELECT_READ);
    c->fd = -1;
  }

  // free pending packet
  if (c->next) {
    c->next->kill();
    c->next = NULL;
  }

  if (IS_PPTP(c)) {
    // cleanup associated GRE connection
    if (c->gre) {
      assert(!IS_PPTP(c->gre));
      cleanup_connection(c->gre);
      c->gre = NULL;
    }
  }
  else {
    // delete acknowledgement timer
    if (c->ack_timer) {
      c->ack_timer->cleanup();
      delete c->ack_timer;
      c->ack_timer = NULL;
    }
    // free from hash by input number
    assert(_inputs.size() > c->input);
    assert(_inputs[c->input] == c);
    _inputs[c->input] = NULL;
  }

  // free from hash by socket descriptor
  assert(_connections.size() > fd);
  assert(_connections[fd] == c);
  _connections[fd] = NULL;

  // delete connection
  delete c;
  c = NULL;

  if (_verbose)
    click_chatter("%s: closed connection %d", declaration().cc(), fd);
}

void
PPTPServer::cleanup(CleanupStage)
{
  if (_fd >= 0) {
    // shut down the listening socket in case we forked
#ifdef SHUT_RDWR
    shutdown(_fd, SHUT_RDWR);
#else
    shutdown(_fd, 2);
#endif
    close(_fd);
    _fd = -1;
  }
  for (int i = 0; i < _connections.size(); i++) {
    if (_connections[i])
      cleanup_connection(_connections[i]);
    assert(!_connections[i]);
  }
}

PPTPServer::Connection *
PPTPServer::initialize_pptp(int listen_fd)
{
  int pptp_fd;
  struct sockaddr_in sin;
  socklen_t sin_len;
  Connection *c = NULL;

  sin_len = sizeof(sin);
  pptp_fd = accept(listen_fd, (struct sockaddr *)&sin, &sin_len);
  if (pptp_fd < 0) {
    if (errno != EAGAIN)
      click_chatter("%s: accept: %s", declaration().cc(), strerror(errno));
    return NULL;    
  }

  c = new Connection(pptp_fd);
  assert(c);

  // hash by socket descriptor
  while (pptp_fd >= _connections.size())
    _connections.push_back(NULL);
  assert(!_connections[pptp_fd]);
  _connections[pptp_fd] = c;

  if (_verbose)
    click_chatter("%s: opened connection %d from %s:%d", declaration().cc(),
		  pptp_fd, IPAddress(sin.sin_addr).unparse().cc(), ntohs(sin.sin_port));

  // nonblocking I/O and close-on-exec for the socket
  fcntl(pptp_fd, F_SETFL, O_NONBLOCK);
  fcntl(pptp_fd, F_SETFD, FD_CLOEXEC);

  add_select(pptp_fd, SELECT_READ);

  return c;
}

PPTPServer::Connection *
PPTPServer::initialize_gre(int pptp_fd)
{
  int gre_fd;
  struct sockaddr_in sin;
  socklen_t sin_len;
  Connection *c = NULL;
  int input;

  for (input = 0; input < ninputs(); input++) {
    if (!_inputs[input])
      break;
  }
  if (input == ninputs()) {
    click_chatter("%s: no more inputs", declaration().cc());
    return NULL;
  }

  // open GRE raw socket
  gre_fd = socket(PF_INET, SOCK_RAW, PPTP_PROTO);
  if (gre_fd < 0) {
    click_chatter("%s: socket: %s", declaration().cc(), strerror(errno));
    return NULL;
  }

  // create connection
  c = new Connection(gre_fd);
  assert(c);

  // hash by socket descriptor
  while (gre_fd >= _connections.size())
    _connections.push_back(NULL);
  assert(!_connections[gre_fd]);
  _connections[gre_fd] = c;

  // hash by input number
  assert(!_inputs[input]);
  _inputs[input] = c;
  c->input = input;

  // associated PPTP connection
  c->pptp = _connections[pptp_fd];
  assert(c->pptp);

  // initialize acknowledgement timer
  c->ack_timer = new Timer(send_ack, (void *)c);
  assert(c->ack_timer);
  c->ack_timer->initialize(this);

  // bind to local address
  sin_len = sizeof(sin);
  if (getsockname(pptp_fd, (struct sockaddr *)&sin, &sin_len) < 0) {
    click_chatter("%s: getsockname: %s", declaration().cc(), strerror(errno));
    goto err;
  }
  assert(sin.sin_family == PF_INET);
  sin.sin_port = htons((short)pptp_fd);
  sin_len = sizeof(sin);
  if (bind(gre_fd, (struct sockaddr *)&sin, sin_len) < 0) {
    click_chatter("%s: bind: %s", declaration().cc(), strerror(errno));
    goto err;
  }

  // connect to remote peer
  sin_len = sizeof(sin);
  if (getpeername(pptp_fd, (struct sockaddr *)&sin, &sin_len) < 0) {
    click_chatter("%s: getsockname: %s", declaration().cc(), strerror(errno));
    goto err;
  }
  assert(sin.sin_family == PF_INET);
  sin.sin_port = htons((short)pptp_fd);
  sin_len = sizeof(sin);
  if (connect(gre_fd, (struct sockaddr *)&sin, sin_len) < 0) {
    click_chatter("%s: connect: %s", declaration().cc(), strerror(errno));
    goto err;
  }

  if (_verbose)
    click_chatter("%s: opened connection %d to %s", declaration().cc(),
		  gre_fd, IPAddress(sin.sin_addr).unparse().cc());

  // nonblocking I/O and close-on-exec for the socket
  fcntl(gre_fd, F_SETFL, O_NONBLOCK);
  fcntl(gre_fd, F_SETFD, FD_CLOEXEC);

  add_select(gre_fd, SELECT_READ);

  return c;

 err:
  cleanup_connection(c);
  return NULL;
}

int
PPTPServer::send_gre(Connection *c, WritablePacket *p)
{
  int fd = c->fd;
  struct pptp_gre_header *gre;
  unsigned header_len = offsetof(struct pptp_gre_header, seq);

  // send sequence number
  if (p->length())
    header_len += sizeof(gre->seq);

  // send acknowledgement number
  if (c->ack_sent != c->seq_recv)
    header_len += sizeof(gre->ack);

  // push GRE header
  p->push(header_len);
  gre = (struct pptp_gre_header *)p->data();
  memset(gre, 0, header_len);

  // set common flags
  gre->flags = PPTP_GRE_FLAG_K;
  gre->ver = PPTP_GRE_VER;
  gre->protocol = htons(PPTP_GRE_PROTO);
  gre->payload_len = htons(p->length() - header_len);
  gre->call_id = htons((short)c->pptp->fd);

  // add sequence number
  if (p->length() > header_len) {
    gre->flags |= PPTP_GRE_FLAG_S;
    gre->seq = htonl(c->seq_sent++);
  }

  // add acknowledgement number
  if (c->ack_sent != c->seq_recv) {
    gre->ver |= PPTP_GRE_FLAG_A;
    if (p->length() > header_len)
      gre->ack = htonl(c->seq_recv);
    else
      gre->seq = htonl(c->seq_recv);
    c->ack_sent = c->seq_recv;
  }

  // send GRE packet
  while (p->length()) {
    int w = write(fd, p->data(), p->length());
    if (w < 0 && errno != EINTR) {
      click_chatter("%s: %s:", declaration().cc(), strerror(errno));
      p->kill();
      return w;
    }
    p->pull(w);
  }

  return 0;
}

void
PPTPServer::send_ack(Timer *, void *thunk)
{
  Connection *c = (Connection *)thunk;
  PPTPServer *ps = (PPTPServer *)c->ps;

  if (c->ack_sent != c->seq_recv) {
    WritablePacket *p = Packet::make(sizeof(struct pptp_gre_header));
    assert(p);
    p->pull(p->length());
    ps->send_gre(c, p);
  }
}

void *
PPTPServer::handle_gre(Connection *c)
{
  int fd = c->fd;
  WritablePacket *p = NULL;
  struct pptp_gre_header *gre;
  unsigned header_len, length;

  assert(IS_GRE(c));

  // allocate packet
  if (!c->next) {
    c->next = Packet::make(PACKET_MAX);
    assert(c->next);
    c->next->take(PACKET_MAX);
  }

  // read data from socket
  p = c->next;
  c->next = NULL;
  assert(p);
  int r;
  do {
    while ((r = read(fd, p->end_data(), p->tailroom())) > 0)
      p->put(r);
  } while (r < 0 && errno == EINTR);

  // unrecoverable error
  if (r < 0 && errno != EAGAIN) {
    click_chatter("%s: read: %s", declaration().cc(), strerror(errno));
    goto err;
  }

  header_len = sizeof(click_ip) + offsetof(struct pptp_gre_header, seq);
  if (p->length() < header_len) {
    // hold out for more data
    c->next = p;
    return NULL;
  }

  gre = (struct pptp_gre_header*)(p->data() + sizeof(click_ip));
  length = 0;

  if (PPTP_GRE_IS_S(gre->flags)) {
    header_len += sizeof(gre->seq);
    // payload present
    length += ntohs(gre->payload_len);
  }
  if (PPTP_GRE_IS_A(gre->ver))
    header_len += sizeof(gre->ack);
  length += header_len;

  // check length
  if (length > PACKET_MAX) {
    click_chatter("%s: bad payload length %d", declaration().cc(), ntohs(gre->payload_len));
    goto err;
  }
  else if (p->length() > length) {
    // trim this packet
    unsigned extra = p->length() - length;
    p->take(extra);
    // allocate next packet
    assert(!c->next);
    c->next = Packet::make(PACKET_MAX);
    assert(c->next);
    // fill next packet
    memcpy(c->next->data(), p->end_data(), extra);
    c->next->take(PACKET_MAX - extra);
  }
  else if (p->length() < length) {
    // hold out for more data
    c->next = p;
    return NULL;
  }

  // protocol errors
  if (((gre->ver) & 0x7f) != PPTP_GRE_VER ||
      (ntohs(gre->protocol) != PPTP_GRE_PROTO) ||
      PPTP_GRE_IS_C(gre->flags) ||
      PPTP_GRE_IS_R(gre->flags) ||
      !PPTP_GRE_IS_K(gre->flags) ||
      (gre->flags & 0xf)) {
    click_chatter("%s: bad GRE header", declaration().cc());
    goto err;
  }
  if (ntohs(gre->call_id) != (short)c->pptp->fd) {
    click_chatter("%s: bad call ID %d", declaration().cc(), ntohs(gre->call_id));
    goto err;
  }

  // XXX check sequence and acknowledgement numbers for validity
  if (PPTP_GRE_IS_S(gre->flags))
    c->seq_recv = ntohl(gre->seq);
  if (PPTP_GRE_IS_A(gre->ver)) {
    if (PPTP_GRE_IS_S(gre->flags))
      c->ack_recv = ntohl(gre->ack);
    else
      c->ack_recv = ntohl(gre->seq);
  }

  // pull IP and GRE headers
  p->pull(header_len);

  // probably GRE acknowledgement
  if (p->length() < sizeof(struct ppp_header))
    p->kill();
  else {
    output(c->input).push(p);
    // schedule acknowledgement
    c->ack_timer->schedule_after_ms(50);
  }

  return c->next;

 err:
  assert(p && p != c->next);
  p->kill();
  // XXX send stop control connection request instead
  cleanup_connection(c->pptp);
  return NULL;
}

void *
PPTPServer::handle_pptp(Connection *c)
{
  int fd = c->fd;
  WritablePacket *p = NULL;
  struct pptp_header *hdr;
  unsigned length;
  uint16_t ctrl_type;

  // allocate packet
  if (!c->next) {
    c->next = Packet::make(PPTP_MAX_CTRL_PCKT_SIZE);
    assert(c->next);
    c->next->take(PPTP_MAX_CTRL_PCKT_SIZE);
  }

  // read data from socket
  p = c->next;
  c->next = NULL;
  assert(p);
  int r;
  do {
    while ((r = read(fd, p->end_data(), p->tailroom())) > 0)
      p->put(r);
  } while (r < 0 && errno == EINTR);

  // unrecoverable error
  if (r < 0 && errno != EAGAIN) {
    click_chatter("%s: read: %s", declaration().cc(), strerror(errno));
    goto err;
  }

  if (p->length() < sizeof(struct pptp_header)) {
    // hold out for more data
    c->next = p;
    return NULL;
  }

  hdr = (struct pptp_header*)p->data();
  length = ntohs(hdr->length);

  // check length
  if (length < sizeof(struct pptp_header) || length > PPTP_MAX_CTRL_PCKT_SIZE) {
    click_chatter("%s: bad message length %d", declaration().cc(), length);
    goto err;
  }
  else if (p->length() > length) {
    // trim this packet
    unsigned extra = p->length() - length;
    p->take(extra);
    // allocate next packet
    assert(!c->next);
    c->next = Packet::make(PPTP_MAX_CTRL_PCKT_SIZE);
    assert(c->next);
    // fill next packet
    memcpy(c->next->data(), p->end_data(), extra);
    c->next->take(PPTP_MAX_CTRL_PCKT_SIZE - extra);
  }
  else if (p->length() < length) {
    // hold out for more data
    c->next = p;
    return NULL;
  }

  // protocol errors
  if (ntohs(hdr->pptp_type) != PPTP_CTRL_MESSAGE) {
    click_chatter("%s: unhandled message type %d", declaration().cc(), ntohs(hdr->pptp_type));
    goto err;
  }
  if (ntohl(hdr->magic) != PPTP_MAGIC_COOKIE) {
    click_chatter("%s: bad magic cookie 0x%08x", declaration().cc(), ntohl(hdr->magic));
    goto err;
  }

  // truncate reply packet
  p->take(p->length());

  // deal with known control types
  ctrl_type = ntohs(hdr->ctrl_type);

  switch (ctrl_type) {

  case START_CTRL_CONN_RQST: {
    struct pptp_start_ctrl_conn_rply *rply = (struct pptp_start_ctrl_conn_rply*)hdr;
    p->put(sizeof(*rply));
    hdr->ctrl_type = htons(START_CTRL_CONN_RPLY);
    rply->version = htons(PPTP_VERSION);
    rply->result_code = CONNECTED;
    rply->error_code = NO_ERROR;
    rply->framing_cap = htons(OUR_FRAMING);
    rply->bearer_cap = htons(OUR_BEARER);
    rply->max_channels = htons(MAX_CHANNELS);
    rply->firmware_rev = htons(PPTP_FIRMWARE_VERSION);
    memset(rply->hostname, 0, MAX_HOSTNAME_SIZE);
    gethostname((char*)rply->hostname, MAX_HOSTNAME_SIZE);
    memset(rply->vendor, 0, MAX_VENDOR_SIZE);
    strncpy((char*)rply->vendor, "click", MAX_VENDOR_SIZE);
    break;
  }

  case STOP_CTRL_CONN_RQST: {
    struct pptp_stop_ctrl_conn_rply *rply = (struct pptp_stop_ctrl_conn_rply*)hdr;
    p->put(sizeof(*rply));
    hdr->ctrl_type = htons(STOP_CTRL_CONN_RPLY);
    rply->result_code = DISCONNECTED;
    rply->error_code = NO_ERROR;
    rply->reserved1 = htons(RESERVED);
    break;
  }

  case OUT_CALL_RQST: {
    struct pptp_out_call_rqst *rqst = (struct pptp_out_call_rqst*)hdr;
    uint16_t call_id_peer = rqst->call_id;
    uint32_t max_bps = rqst->max_bps;
    uint16_t pckt_recv_size = rqst->pckt_recv_size;
    struct pptp_out_call_rply *rply = (struct pptp_out_call_rply*)hdr;
    // (re)initialize GRE raw socket
    if (c->gre)
      cleanup_connection(c->gre);
    if (!(c->gre = initialize_gre(fd)))
      goto err;
    p->put(sizeof(*rply));
    hdr->ctrl_type = htons(OUT_CALL_RPLY);
    rply->call_id = htons((short)fd);
    rply->call_id_peer = call_id_peer;
    rply->result_code = CONNECTED;
    rply->error_code = NO_ERROR;
    rply->cause_code = NO_ERROR;
    rply->speed = max_bps;
    rply->pckt_recv_size = pckt_recv_size;
    rply->pckt_delay = htons(PCKT_PROCESS_DELAY);
    rply->channel_id = htonl(CHANNEL_ID);
    break;
  }

  case ECHO_RQST: {
    struct pptp_echo_rqst *rqst = (struct pptp_echo_rqst *)hdr;
    uint32_t identifier = rqst->identifier;
    struct pptp_echo_rply *rply = (struct pptp_echo_rply *)hdr;
    p->put(sizeof(*rply));
    hdr->ctrl_type = htons(ECHO_RPLY);
    rply->identifier = identifier;
    rply->result_code = CONNECTED;
    rply->error_code = NO_ERROR;
    rply->reserved1 = htons(RESERVED);
    break;
  }

  case CALL_CLR_RQST: {
    struct pptp_call_disconn_ntfy *ntfy = (struct pptp_call_disconn_ntfy *)hdr;
    // close GRE raw socket
    if (c->gre) {
      cleanup_connection(c->gre);
      c->gre = NULL;
    }
    p->put(sizeof(*ntfy));
    hdr->ctrl_type = htons(CALL_DISCONN_NTFY);
    ntfy->call_id = htons((short)fd);
    ntfy->result_code = CALL_CLEAR_REQUEST;
    ntfy->error_code = NO_ERROR;
    ntfy->cause_code = htons(NO_ERROR);
    ntfy->reserved1 = htons(RESERVED);
    memset(ntfy->call_stats, 0, 128);
    break;
  }

  case SET_LINK_INFO:
  case ECHO_RPLY:
  case STOP_CTRL_CONN_RPLY:
  case CALL_DISCONN_NTFY:
    break;

  default:
    click_chatter("%s: unhandled control type %d", declaration().cc(), ntohs(hdr->ctrl_type));
    goto err;
  }

  if (p->length()) {
    // set common header fields
    hdr->length = htons(p->length());
    hdr->pptp_type = htons(PPTP_CTRL_MESSAGE);
    hdr->magic = htonl(PPTP_MAGIC_COOKIE);
    hdr->reserved0 = htons(RESERVED);

    // send reply
    while (p->length()) {
      int w = write(fd, p->data(), p->length());
      if (w < 0 && errno != EINTR) {
	click_chatter("%s: %s:", declaration().cc(), strerror(errno));
	goto err;
      }
      p->pull(w);
    }
  }

  if (ctrl_type == STOP_CTRL_CONN_RQST)
    goto err;
 
  p->kill();
  return c->next;

 err:
  assert(p && p != c->next);
  p->kill();
  cleanup_connection(c);
  return NULL;
}

void
PPTPServer::selected(int fd)
{
  Connection *c;

  if (fd == _fd) {
    c = initialize_pptp(fd);
    if (!c)
      return;
  }
  else
    c = _connections[fd];

  assert(c);

  if (IS_PPTP(c))
    while (handle_pptp(c));
  else
    while (handle_gre(c));
}

void
PPTPServer::push(int input, Packet *p)
{
  Connection *c = _inputs[input];
  if (c) {
    assert(IS_GRE(c));
    // XXX check for error
    send_gre(c, (WritablePacket *)p);
  }
  p->kill();
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(PPTPServer)
