/*
 * leasehash.{cc,hh} -- hand out leases based on hash of mac addr
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
#include <click/crc32.h>
#include "dhcpoptionutil.hh"
#include "leasehash.hh"

LeaseHash::LeaseHash()
{
}

LeaseHash::~LeaseHash()
{
}

IPAddress 
LeaseHash::hash(EtherAddress eth) 
{
	u_int32_t crc = update_crc(0, (char *)eth.data(), 6);
	return IPAddress((_subnet.addr() & 0xff) |
			 (~0xff) & crc);
}
void *
LeaseHash::cast(const char *n) 
{
	if (strcmp(n, "LeaseHash") == 0)
		return (LeaseHash *)this;
	else if (strcmp(n, "LeaseTable") == 0) 
		return (LeaseHash *)this;
	return 0;
}

Lease *
LeaseHash::new_lease_any(EtherAddress eth) 
{
	IPAddress ip = hash(eth);
	Lease *l = LeaseTable::rev_lookup(eth);
	if (l) {
		return l;
	} else {
		Lease l;
		l._eth = eth;
		l._ip = ip;
		l._start = Timestamp::now();
		l._end = l._start + Timestamp(60, 0);
		l._duration = l._end - l._start;
		insert(l);
		return lookup(ip);
	}
}

Lease *
LeaseHash::new_lease(EtherAddress eth, IPAddress) 
{
	/* ignore the requested ip */
	return new_lease_any(eth);
}
bool
LeaseHash::insert(Lease l) {
	return LeaseTable::insert(l);
}

void
LeaseHash::remove(EtherAddress eth) {
	return LeaseTable::remove(eth);	
}

void
LeaseHash::remove(IPAddress ip) {
	Lease *l = lookup(ip);
	remove(l->_eth);
}

int
LeaseHash::configure( Vector<String> &conf, ErrorHandler *errh )
{
	if (cp_va_parse(conf, this, errh,
			cpEtherAddress, "eth addr", &_eth, 
			cpIPAddress, "subnet ip mask", &_subnet,
			cpEnd) < 0) {
		return -1;
	}
	_ip = hash(_eth);
	return 0;
}


void 
LeaseHash::add_handlers()
{
	LeaseTable::add_handlers();
}

EXPORT_ELEMENT(LeaseHash)
#include <click/dequeue.cc>
#include <click/vector.cc>
template class DEQueue<IPAddress>;
