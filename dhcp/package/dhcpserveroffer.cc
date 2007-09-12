/*
 * checkdhcpmsg.{cc,hh} -- respond to a dhcp discover
 * Lih Chen
 * 
 * Copyright (c) 2004 Regents of the University of California
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

#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <clicknet/udp.h>

#include "dhcp_common.hh"
#include "dhcpserveroffer.hh"
#include "dhcpoptionutil.hh"


#define OFFER_TIMEOUT 10
#define OFFER_NO_TIMEOUT 1

DHCPServerOffer::DHCPServerOffer()
{
}

DHCPServerOffer::~DHCPServerOffer()
{
}

int
DHCPServerOffer::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_kparse(conf, this, errh,
		   "LEASES", cpkP+cpkM, cpElement, &_leases,
		   cpEnd) < 0 ) {
	  return -1;
  }
  return 0;
}


void 
DHCPServerOffer::push(int, Packet *p)
{

	click_ether *eh = (click_ether *) p->data();
	dhcpMessage *discover_msg 
		= (dhcpMessage*)(p->data() + sizeof(click_ether) + 
				 sizeof(click_udp) + sizeof(click_ip));
	EtherAddress eth(discover_msg->chaddr);
	IPAddress client_request_ip;
	Lease *l = 0;
	const uint8_t *opt = DHCPOptionUtil::fetch(p, DHO_DHCP_REQUESTED_ADDRESS, 4);
	if (opt) {
		client_request_ip = IPAddress(opt);
		l = _leases->new_lease(eth, client_request_ip);
	}
	if (!l) {
		l = _leases->new_lease_any(eth);
	}
	if (l) {
		Packet *o = make_offer_packet(discover_msg, l);
		o = DHCPOptionUtil::push_dhcp_udp_header(o, _leases->_ip);
		WritablePacket *q = o->push_mac_header(14);

		click_ether *eh2 = (click_ether *)q->data();
		memcpy(eh2->ether_shost, _leases->_eth.data(), 6);
		memcpy(eh2->ether_dhost, eh->ether_shost, 6);
		memset(eh2->ether_dhost, 0xff, 6);
		eh2->ether_type = htons(ETHERTYPE_IP);
		output(0).push(q);
	}
	p->kill();
}

Packet*
DHCPServerOffer::make_offer_packet(dhcpMessage *discover_dm, Lease *l)
{
  WritablePacket *offer_q = Packet::make(sizeof(dhcpMessage));
  memset(offer_q->data(), '\0', offer_q->length());
  dhcpMessage *dhcp_offer = 
    reinterpret_cast<dhcpMessage *>(offer_q->data());
  uint8_t *option_ptr;

  dhcp_offer->op = DHCP_BOOTREPLY;
  dhcp_offer->htype = ARPHRD_ETHER;
  dhcp_offer->hlen = 6;
  dhcp_offer->hops = 0;
  dhcp_offer->xid = discover_dm->xid; 
  dhcp_offer->secs = 0;
  dhcp_offer->flags = 0;
  dhcp_offer->ciaddr = 0;
  dhcp_offer->yiaddr = l->_ip;
  dhcp_offer->siaddr = 0;
  dhcp_offer->giaddr = 0;
  memcpy(dhcp_offer->chaddr, discover_dm->chaddr, 16);
  dhcp_offer->magic = DHCP_MAGIC;
  //option field
  option_ptr = dhcp_offer->options;
  *option_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *option_ptr++ = 1;
  *option_ptr++ = DHCP_OFFER;
  
  *option_ptr++ = DHO_DHCP_LEASE_TIME;
  uint32_t duration = l->_duration.sec();
  *option_ptr++ = 4;
  memcpy(option_ptr, &duration, 4);
  option_ptr += 4;

  *option_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  uint32_t server_ip = l->_ip;
  *option_ptr++ = 4;
  memcpy(option_ptr, &server_ip, 4);
  option_ptr += 4;
  
  *option_ptr = DHO_END;
  
  return offer_q;
}

void
DHCPServerOffer::add_handlers()
{
}

EXPORT_ELEMENT(DHCPServerOffer)
ELEMENT_REQUIRES(DHCPOptionUtil)
