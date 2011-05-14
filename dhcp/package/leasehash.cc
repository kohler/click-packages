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
#include <click/args.hh>
#include <click/etheraddress.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/straccum.hh>
#include <click/crc32.h>
#include "leasehash.hh"
CLICK_DECLS

LeaseHash::LeaseHash()
{
}

LeaseHash::~LeaseHash()
{
}

IPAddress 
LeaseHash::hash(EtherAddress eth) 
{
	uint32_t crc = update_crc(0, (char *)eth.data(), 6);
	return IPAddress((_subnet.addr() & 0xff) |
			 (~0xff & crc));
}
void *
LeaseHash::cast(const char *n) 
{
    if (strcmp(n, "LeaseHash") == 0 || strcmp(n, "DHCPLeaseHash") == 0)
	return (LeaseHash *) this;
    else
	return DHCPLeaseTable::cast(n);
}

Lease *
LeaseHash::new_lease_any(EtherAddress eth) 
{
	IPAddress ip = hash(eth);
	Lease *l = DHCPLeaseTable::rev_lookup(eth);
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

int
LeaseHash::configure( Vector<String> &conf, ErrorHandler *errh )
{
    if (Args(conf, this, errh)
	.read_mp("ETH", _eth)
	.read_mp("MASK", _subnet)
	.complete() < 0)
	return -1;
    _ip = hash(_eth);
    return 0;
}


EXPORT_ELEMENT(LeaseHash LeaseHash-LeaseHash)
CLICK_ENDDECLS
