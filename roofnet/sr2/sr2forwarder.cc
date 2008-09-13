/*
 * SR2Forwarder.{cc,hh} -- Source Route data path implementation
 * Robert Morris
 * John Bicket
 *
 * Copyright (c) 1999-2001 Massachusetts Institute of Technology
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
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/ether.h>
#include "sr2forwarder.hh"
#include "sr2packet.hh"
#include "elements/ethernet/arptable.hh"
CLICK_DECLS

SR2Forwarder::SR2Forwarder()
  :  _ip(),
     _eth(),
     _et(0),
     _datas(0), 
     _databytes(0),
     _arp_table(0)
{
}

SR2Forwarder::~SR2Forwarder()
{
}

int
SR2Forwarder::configure (Vector<String> &conf, ErrorHandler *errh)
{
	int res;
	res = cp_va_kparse(conf, this, errh,
			   "ETHTYPE", 0, cpUnsignedShort, &_et,
			   "IP", 0, cpIPAddress, &_ip,
			   "ETH", 0, cpEtherAddress, &_eth,
			   "ARP", 0, cpElement, &_arp_table,
			   cpEnd);
	
	if (!_et) 
		return errh->error("ETHTYPE not specified");
	if (!_ip) 
		return errh->error("IP not specified");
	if (!_eth) 
		return errh->error("ETH not specified");
	if (!_arp_table) 
		return errh->error("ARPTable not specified");
	
	if (_arp_table->cast("ARPTable") == 0) 
		return errh->error("ARPTable element is not a ARPTable");
	
	if (res < 0) {
		return res;
	}
	return res;
}

int
SR2Forwarder::initialize (ErrorHandler *)
{
	return 0;
}

Packet *
SR2Forwarder::encap(Packet *p_in, Vector<IPAddress> r, int flags)
{
	assert(r.size() > 1);
	int hops = r.size() - 1;
	unsigned extra = sr2packet::len_wo_data(hops) + sizeof(click_ether);
	unsigned payload_len = p_in->length();
	uint16_t ether_type = htons(_et);

	WritablePacket *p = p_in->push(extra);
	
	assert(extra + payload_len == p_in->length());
	
	
	int next = index_of(r, _ip) + 1;
	if (next < 0 || next >= r.size()) {
		click_chatter("SR2Forwarder %s: encap couldn't find %s (%d) in path %s",
			      name().c_str(), _ip.unparse().c_str(),
			      next, path_to_string(r).c_str());
		p_in->kill();
		return (0);
	}
	EtherAddress eth_dest = _arp_table->lookup(r[next]);
	if (eth_dest.is_group()) {
		click_chatter("SR2Forwarder %s: arp lookup failed for %s",
			      name().c_str(), r[next].unparse().c_str());
	}
	
	memcpy(p->data(), eth_dest.data(), 6);
	memcpy(p->data() + 6, _eth.data(), 6);
	memcpy(p->data() + 12, &ether_type, 2);	
	
	struct sr2packet *pk = (struct sr2packet *) (p->data() + sizeof(click_ether));
	memset(pk, '\0', sr2packet::len_wo_data(hops));
	
	pk->_version = _sr2_version;
	pk->_type = SR2_PT_DATA;
	pk->set_data_len(payload_len);
	
	pk->set_num_links(hops);
	pk->set_next(next);
	pk->set_flag(flags);
	int i;
	for (i = 0; i < hops; i++) {
		pk->set_link_node(i, r[i]);
	}
	
	pk->set_link_node(hops, r[r.size()-1]);
	pk->set_data_seq(0);

	/* set the ip header anno */
	const click_ip *ip = reinterpret_cast<const click_ip *>
		(p->data() + pk->hlen_wo_data() + sizeof(click_ether));
	p->set_ip_header(ip, sizeof(click_ip));
	return p;
}

void
SR2Forwarder::push(int port, Packet *p_in)
{
	WritablePacket *p = p_in->uniqueify();
	click_ether *eh = 0;
	struct sr2packet *pk = 0;
	EtherAddress eth_dest;
	if (!p) {
		return;
	}
	eh = (click_ether *) p->data();
	pk = (struct sr2packet *) (eh+1);
	
	if (pk->_type != SR2_PT_DATA) {
		click_chatter("SR2Forwarder %s: bad packet_type %04x",
			      _ip.unparse().c_str(), pk->_type);
		goto bad;
	}

	if (port == 0 && pk->get_link_node(pk->next()) != _ip){
		if (EtherAddress(eh->ether_dhost).is_group()) {
			/* 
			 * if the arp doesn't have a ethernet address, it
			 * will broadcast the packet. in this case,
			 * don't complain. But otherwise, something's up
			 */
			click_chatter("%{element} data not for me seq %d %d/%d ip %s eth %s",
				      name().c_str(), pk->data_seq(), pk->next(), pk->num_links(),
				      pk->get_link_node(pk->next()).unparse().c_str(),
				      EtherAddress(eh->ether_dhost).unparse().c_str());
		}
		goto bad;
	}

	{
		/* set the ip header anno */
		const click_ip *ip = reinterpret_cast<const click_ip *>(pk->data());
		p->set_ip_header(ip, sizeof(click_ip));
	}
	
	if (pk->next() == pk->num_links()){
		/*
		 * I am the ultimate consumer of this packet.  set the
		 * dst to the gateway it came from. this is kinda
		 * weird.
		 */
		SET_MISC_IP_ANNO(p, pk->get_link_node(0));
		output(1).push(p);
		return;
	} 
	pk->set_next(pk->next() + 1);
	eth_dest = _arp_table->lookup(pk->get_link_node(pk->next()));
	if (eth_dest.is_group()) {
		click_chatter("%{element}::%s arp lookup failed for %s",
			      this, __func__,
			      pk->get_link_node(pk->next()).unparse().c_str());
	}
	memcpy(eh->ether_dhost, eth_dest.data(), 6);
	memcpy(eh->ether_shost, _eth.data(), 6);
	output(0).push(p);
	return;
 bad:
	p->kill();
	return;
	
}

String
SR2Forwarder::print_stats()
{
	return String(_datas) + " datas sent\n" + String(_databytes) + " bytes of data sent\n";
}

enum { H_STATS };

String
SR2Forwarder::read_handler(Element *e, void *user_data)
{
    SR2Forwarder *sr2f = static_cast<SR2Forwarder *>(e);
    switch (reinterpret_cast<uintptr_t>(user_data)) {
    case H_STATS:
	return sr2f->print_stats();
    }
    return String();
}

void
SR2Forwarder::add_handlers()
{
    add_read_handler("stats", read_handler, H_STATS);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SR2Forwarder)
