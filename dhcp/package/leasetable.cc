/*
 * leasetable.{cc,hh} -- track dhcp leases
 * John Bicket
 *
 * Copyright (c) 2005 Massachusetts Institute of Technology
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
#include <click/etheraddress.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/bighashmap.cc>
#include <click/vector.cc>
#include <click/straccum.hh>
#include "leasetable.hh"

DHCPLeaseTable::DHCPLeaseTable()
{
}

DHCPLeaseTable::~DHCPLeaseTable()
{
}

int
DHCPLeaseTable::configure( Vector<String> &conf, ErrorHandler *errh )
{
  if (cp_va_kparse(conf, this, errh,
		   "ETH", cpkP+cpkM, cpEtherAddress, &_eth, 
		   "IP", cpkP+cpkM, cpIPAddress, &_ip,
		   "MASK", cpkP+cpkM, cpIPAddress, &_subnet,
		   cpEnd) < 0 ) {
	  return -1;
  }
  return 0;
}

void *
DHCPLeaseTable::cast(const char *n)
{
	if (strcmp(n, "DHCPLeaseTable") == 0)
		return (DHCPLeaseTable *)this;
	return 0;
}

Lease *
DHCPLeaseTable::rev_lookup(EtherAddress eth)
{
	IPAddress *ip = _ips.findp(eth);
	return ip ? _leases.findp(*ip) : 0;
}

Lease *
DHCPLeaseTable::lookup(IPAddress ip)
{
	return _leases.findp(ip);
}

void
DHCPLeaseTable::remove(EtherAddress eth) 
{
    if (Lease *l = rev_lookup(eth)) {
	IPAddress ip = l->_ip;
	_leases.remove(ip);
	_ips.remove(eth);
    }
}

bool
DHCPLeaseTable::insert(Lease l) {
	IPAddress ip = l._ip;
	EtherAddress eth = l._eth;
	_ips.insert(eth, ip);
	_leases.insert(ip, l);
	return true;
}

enum {H_LEASES};
String
DHCPLeaseTable::read_handler(Element *e, void *thunk)
{
	DHCPLeaseTable *lt = (DHCPLeaseTable *)e;
	switch ((uintptr_t) thunk) {
	case H_LEASES: {
		StringAccum sa;
		for (LeaseIter iter = lt->_leases.begin(); iter.live(); iter++) {
			Lease l = iter.value();
			sa << "lease " << l._ip << " {\n";
			sa << "  starts " << l._start.sec() << ";\n";
			sa << "  ends " << l._end.sec() << ";\n";
			sa << "  hardware ethernet " << l._eth << ";\n";
			sa << "}\n";
		}
		return sa.take_string() + "\n";
	}
	default:
		return String();
	}
}
void
DHCPLeaseTable::add_handlers() 
{
	add_read_handler("leases", read_handler, (void *) H_LEASES);
}

EXPORT_ELEMENT(DHCPLeaseTable)

