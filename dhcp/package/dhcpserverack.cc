/*
 * checkdhcpmsg.{cc,hh} -- respond to a dhcp request
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

#include "dhcpserverack.hh"
#include "dhcp_common.hh"
#include "dhcpoptionutil.hh"
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

CLICK_DECLS

DHCPServerACKorNAK::DHCPServerACKorNAK()
{
}

DHCPServerACKorNAK::~DHCPServerACKorNAK()
{
}

int 
DHCPServerACKorNAK::initialize(ErrorHandler *)
{
	return 0;
}

int 
DHCPServerACKorNAK::configure(Vector<String> &conf, ErrorHandler *errh)
{
	if(cp_va_kparse(conf, this, errh,
			"LEASES", cpkP+cpkM, cpElement, &_leases,
			cpEnd) < 0) {
		return -1;
	}
	return 0;
}

void 
DHCPServerACKorNAK::push(int, Packet *p)
{
	click_ether *eh = (click_ether *) p->data();
	dhcpMessage *req_msg 
		= (dhcpMessage*)(p->data() + sizeof(click_ether) + 
				 sizeof(click_udp) + sizeof(click_ip));
	Packet *q = 0;
	IPAddress ciaddr = IPAddress(req_msg->ciaddr);
	EtherAddress eth(req_msg->chaddr);
	IPAddress requested_ip = IPAddress(0);
	Lease *lease = _leases->rev_lookup(eth);
	IPAddress server = IPAddress(0);
	const uint8_t *o = DHCPOptionUtil::fetch(p, DHO_DHCP_SERVER_IDENTIFIER, 4);
	if (o)
	    server = IPAddress(o);
	
	o = DHCPOptionUtil::fetch(p, DHO_DHCP_REQUESTED_ADDRESS, 4);
	if (o)
	    requested_ip = IPAddress(o);

	if (!ciaddr && !requested_ip) {
		/* this is outside of the spec, but dhclient seems to
		   do this, so just give it an address */
		if (!lease) {
			lease = _leases->new_lease_any(eth);
		}
		if (lease) {
			q = make_ack_packet(p, lease);
		}
	} else if (server && !ciaddr && requested_ip) {
		/* SELECTING */
		if(lease && lease->_ip == requested_ip) {
			q = make_ack_packet(p, lease);
			lease->_valid = true;
		}
	} else if (!server && requested_ip && !ciaddr) {
		/* INIT-REBOOT */
		bool network_is_correct = true;
		if (!network_is_correct) {
			q = make_nak_packet(p, lease);
		} else {	  
			if (lease && lease->_ip == requested_ip) {
				if (lease->_end <  Timestamp::now() ) {
					q = make_nak_packet(p, lease);
				} else {
					lease->_valid = true;
					q = make_ack_packet(p, lease);
				}
			}
		}
	} else if (!server && !requested_ip && ciaddr) {
		/* RENEW or REBIND */
		if (lease) {
			lease->_valid = true;
			lease->extend();
			q = make_ack_packet(p, lease);
		}
	} else {
		click_chatter("%s:%d\n", __FILE__, __LINE__);
	}
	
	if (q) {
		
		Packet *o = DHCPOptionUtil::push_dhcp_udp_header(q, _leases->_ip);
		WritablePacket *s = o->push_mac_header(14);
		
		click_ether *eh2 = (click_ether *)s->data();
		memcpy(eh2->ether_shost, _leases->_eth.data(), 6);
		memcpy(eh2->ether_dhost, eh->ether_shost, 6);
		memset(eh2->ether_dhost, 0xff, 6);
		eh2->ether_type = htons(ETHERTYPE_IP);
		output(0).push(s);
	}
	p->kill();
}


Packet*
DHCPServerACKorNAK::make_ack_packet(Packet *p, Lease *lease)
{
  dhcpMessage *req_msg 
	  = (dhcpMessage*)(p->data() + sizeof(click_ether) + 
			   sizeof(click_udp) + sizeof(click_ip));
  WritablePacket *ack_q = Packet::make(sizeof(dhcpMessage));
  memset(ack_q->data(), '\0', ack_q->length());
  dhcpMessage *dhcp_ack =
    reinterpret_cast<dhcpMessage *>(ack_q->data());
  uint8_t *options_ptr;

  dhcp_ack->op = DHCP_BOOTREPLY;
  dhcp_ack->htype = ARPHRD_ETHER;
  dhcp_ack->hlen = 6;
  dhcp_ack->hops = 0;
  dhcp_ack->xid = req_msg->xid; 
  dhcp_ack->secs = 0;
  dhcp_ack->flags = 0;
  dhcp_ack->ciaddr = req_msg->ciaddr;
  dhcp_ack->yiaddr = lease->_ip;
  dhcp_ack->siaddr = 0;
  dhcp_ack->flags = req_msg->flags;
  dhcp_ack->giaddr = req_msg->giaddr;
  memcpy(dhcp_ack->chaddr, req_msg->chaddr, 16);
  dhcp_ack->magic = DHCP_MAGIC;  
  options_ptr = dhcp_ack->options;
  *options_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *options_ptr++ = 1;
  *options_ptr++ = DHCP_ACK;
  *options_ptr++ = DHO_DHCP_LEASE_TIME;
  *options_ptr++ = 4;
  uint32_t duration = lease->_duration.sec(); 
  duration = htonl(duration);
  memcpy(options_ptr, &duration, 4);
  options_ptr += 4;
  *options_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  *options_ptr++ = 4;
  uint32_t server_ip = _leases->_ip;
  memcpy(options_ptr, &server_ip, 4);
  options_ptr += 4;
  *options_ptr = DHO_END;
  
  return ack_q;
}

Packet*
DHCPServerACKorNAK::make_nak_packet(Packet *p, Lease *)
{
  dhcpMessage *req_msg =
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  
  WritablePacket *nak_q = Packet::make(sizeof(dhcpMessage));
  memset(nak_q->data(), '\0', nak_q->length());
  dhcpMessage *dhcp_nak =
    reinterpret_cast<dhcpMessage *>(nak_q->data());
  uint8_t *options_ptr;
  
  dhcp_nak->op = DHCP_BOOTREPLY;
  dhcp_nak->htype = ARPHRD_ETHER;
  dhcp_nak->hlen = 6;
  dhcp_nak->hops = 0;
  dhcp_nak->xid = req_msg->xid;
  dhcp_nak->secs = 0;
  dhcp_nak->flags = 0;
  dhcp_nak->ciaddr = 0;
  dhcp_nak->yiaddr = 0;
  dhcp_nak->siaddr = 0;
  dhcp_nak->flags = req_msg->flags;
  dhcp_nak->giaddr = req_msg->giaddr;
  memcpy(dhcp_nak->chaddr, req_msg->chaddr, 16);
  dhcp_nak->magic = DHCP_MAGIC;
  options_ptr = dhcp_nak->options;
  *options_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *options_ptr++ = 1;
  *options_ptr++ = DHCP_NACK;
  *options_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  *options_ptr++ = 4;
  uint32_t server_ip = _leases->_ip;
  memcpy(options_ptr, &server_ip, 4);
  options_ptr += 4;
  *options_ptr = DHO_END;
  
  return nak_q;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(DHCPServerACKorNAK)
ELEMENT_REQUIRES(DHCPOptionUtil)

