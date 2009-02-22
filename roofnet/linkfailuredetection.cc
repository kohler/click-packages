/*
 * linkfailuredetection.{cc,hh} -- sets wifi txrate annotation on a packet
 * John Bicket
 *
 * Copyright (c) 2003 Massachusetts Institute of Technology
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
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include <clicknet/wifi.h>
#include <click/router.hh>
#include "linkfailuredetection.hh"
CLICK_DECLS

LinkFailureDetection::LinkFailureDetection()
  : _threshold(1)
{
  static unsigned char bcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  _bcast = EtherAddress(bcast_addr);
}

LinkFailureDetection::~LinkFailureDetection()
{
}

int
LinkFailureDetection::configure(Vector<String> &conf, ErrorHandler *errh)
{

  if (conf.size() != 2) {
    return errh->error("LinkFailureDetection need two args THRESHOLD and HANLDER");
  }
  
  if (!cp_integer(conf[0], &_threshold) || _threshold < 1) {
    return errh->error("THRESHOLD must be >= 1");
  }

  if (!cp_handler_name(conf[1], &_handler_e, &_handler_name, this, errh)) {
    return errh->error("invalid handler %s", conf[1].c_str());
  }
  return 0;
}


void 
LinkFailureDetection::call_handler(EtherAddress dst) {
  ErrorHandler *errh = ErrorHandler::default_handler();
  
  const Handler *h = Router::handler(_handler_e, _handler_name);
  if (!h) {
    errh->error("%s: no handler `%s'", name().c_str(), 
		Handler::unparse_name(_handler_e, _handler_name).c_str());
  }
  
  if (h->writable()) {
    ContextErrorHandler cerrh
	(errh, "In write handler %<%s%>:", h->unparse_name(_handler_e).c_str());
    h->call_write(dst.unparse(), _handler_e, &cerrh);
  } else {
    errh->error("%s: no write handler `%s'", 
		name().c_str(), 
		h->unparse_name(_handler_e).c_str());
  }

}
Packet *
LinkFailureDetection::simple_action(Packet *p_in)
{
  click_ether *eh = (click_ether *) p_in->data();
  EtherAddress dst = EtherAddress(eh->ether_dhost);

  if (dst == _bcast) {
    /* don't record bcast packets */
    return p_in;
  }
  click_wifi_extra *ceh = (click_wifi_extra *) p_in->user_anno();
  bool success = !(ceh->flags & WIFI_EXTRA_TX_FAIL);

  DstInfo *nfo = &_neighbors[dst];
  if (!nfo->_eth) {
      nfo->_eth = dst;
  }
  nfo->_last_received.set_now();
  if (success) {
    nfo->_successive_failures = 0;
    nfo->_notified = false;
  } else {
    nfo->_successive_failures++;
    StringAccum sa;
    sa  << nfo->_last_received;
    if (0 == nfo->_successive_failures % _threshold) {
      click_chatter("%{element}: succ. packet %d ethtype %x %s at %s\n",
		    this,
		    nfo->_successive_failures,
		    ntohs(eh->ether_type),
		    nfo->_eth.unparse().c_str(),
		    sa.take_string().c_str());


      /* call handler */
      call_handler(dst);
      nfo->_notified = true;
    }
  }
  return p_in;
}
String
LinkFailureDetection::static_print_stats(Element *e, void *)
{
  LinkFailureDetection *n = (LinkFailureDetection *) e;
  return n->print_stats();
}

String
LinkFailureDetection::print_stats() 
{
  Timestamp now = Timestamp::now();
  
  StringAccum sa;
  for (NIter iter = _neighbors.begin(); iter.live(); iter++) {
    DstInfo n = iter.value();
    Timestamp age = now - n._last_received;
    sa << n._eth.unparse().c_str();
    sa << " successive_failures: " << n._successive_failures;
    if (n._notified) {
      sa << "*";
    }
    sa << " last_received: " << age << "\n";
  }
  return sa.take_string();
}
void
LinkFailureDetection::add_handlers()
{
  add_read_handler("stats", static_print_stats, 0);

}

CLICK_ENDDECLS
EXPORT_ELEMENT(LinkFailureDetection)

