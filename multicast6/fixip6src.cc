/*
 * fixip6src.{cc,hh} -- element sets IP source to given value
 * Martin Hoffmann
 *
 * Copyright (c) 2005 University of Bristol
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
#include "fixip6src.hh"
#include <click/glue.hh>
#include <click/confparse.hh>
#include <click/error.hh>


CLICK_DECLS



FixIP6Src::FixIP6Src()
{
}

FixIP6Src::~FixIP6Src()
{
}

void
FixIP6Src::printIP6(IP6Address group)
{
  click_chatter("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", (unsigned char)(* group.data() + 0),(unsigned char)(* (group.data() + 1)), (unsigned char)(* (group.data() + 2)), (unsigned char)(* (group.data() + 3)),(unsigned char)(* (group.data() + 4)), (unsigned char)(* (group.data() + 5)), (unsigned char)(* (group.data() + 6)), (unsigned char)(* (group.data() + 7)), (unsigned char)(* (group.data() + 8)), (unsigned char)(* (group.data() + 9)), (unsigned char)(* (group.data() + 10)), (unsigned char)(* (group.data() + 11)), (unsigned char)(* (group.data() + 12)), (unsigned char)(* (group.data() + 13)), (unsigned char)(* (group.data() + 14)), (unsigned char)(* (group.data() + 15))  ); 
}

int
FixIP6Src::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("FIXPIMSOURCE wrong number of arguments;");
  
  // get PIMForwardingTable element
  if (!cp_ip6_address(conf[0], (unsigned char *) &fixip6addr)) { 
	return -1;
  }


  return 0;
}

WritablePacket *
FixIP6Src::fix_it(Packet *p_in)
{
  WritablePacket *q = p_in->uniqueify();
  click_ip6 *ip = (click_ip6 *)q->data();
  ip->ip6_src = IP6Address(fixip6addr);

  return q;
}

Packet *
FixIP6Src::simple_action(Packet *p_in)
{
  Packet *p = fix_it(p_in);
  return p_in;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FixIP6Src)
ELEMENT_MT_SAFE(FixIP6Src)
