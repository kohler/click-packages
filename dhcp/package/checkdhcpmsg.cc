/*
 * checkdhcpmsg.{cc,hh} -- check the magic bytes of a dhcp message
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

#include "dhcp_common.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include "checkdhcpmsg.hh"

#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

CLICK_DECLS

CheckDHCPMsg::CheckDHCPMsg()
{
}

CheckDHCPMsg::~CheckDHCPMsg()
{
}

Packet*
CheckDHCPMsg::simple_action(Packet *p)
{
	dhcpMessage *dm = (dhcpMessage*)(((char *) p->ip_header()) +
					 sizeof(click_ip) + 
					 sizeof(click_udp));
	
	if (dm->magic != DHCP_MAGIC) {
		click_chatter("%s, %d bad magic 0x%08x vs 0x%08x", 
			      __FILE__, __LINE__, 
			      ntohl(dm->magic), ntohl(DHCP_MAGIC));
		checked_output_push(1, p);
		return 0;
	}
	return p;
}
CLICK_ENDDECLS
EXPORT_ELEMENT(CheckDHCPMsg)
