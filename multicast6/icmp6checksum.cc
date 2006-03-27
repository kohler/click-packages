/*
 * icmp6checksum.{cc,hh} -- element computes an ICMPv6 checksum
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
#include "icmp6checksum.hh"
#include "mld.hh"
#include <click/glue.hh>
#include <click/error.hh>


CLICK_DECLS

ICMP6Checksum::ICMP6Checksum()
{
}

ICMP6Checksum::~ICMP6Checksum()
{
}

void
ICMP6Checksum::printIP6(IP6Address group)
{
  click_chatter("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", (unsigned char)(* group.data() + 0),(unsigned char)(* (group.data() + 1)), (unsigned char)(* (group.data() + 2)), (unsigned char)(* (group.data() + 3)),(unsigned char)(* (group.data() + 4)), (unsigned char)(* (group.data() + 5)), (unsigned char)(* (group.data() + 6)), (unsigned char)(* (group.data() + 7)), (unsigned char)(* (group.data() + 8)), (unsigned char)(* (group.data() + 9)), (unsigned char)(* (group.data() + 10)), (unsigned char)(* (group.data() + 11)), (unsigned char)(* (group.data() + 12)), (unsigned char)(* (group.data() + 13)), (unsigned char)(* (group.data() + 14)), (unsigned char)(* (group.data() + 15))  ); 
}



// This is a rather short version, you might want to extend this element and implement some more
// functionality. It does not check whether it is feeded with proper icmpv6 messages or not.
// You have to make sure only ICMPv6 packets are handed to this element because it does not check the packet it receives.
WritablePacket *
ICMP6Checksum::addchecksum(Packet *p_in)
{
  WritablePacket *q = p_in->uniqueify();
  const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( q->data());
  char* datapoint=(char *) q->data();
  hopbyhopheader *hopbyhop=(hopbyhopheader *) (q->data() + sizeof(*ip));
  mldv2querie *igp=(mldv2querie *)((char *)hopbyhop + sizeof(*hopbyhop));

  unsigned short chk=in6_cksum(&ip->ip6_src, &ip->ip6_dst, htons(28), 0x3a, 0x00, (unsigned char *)igp, htons(sizeof(*igp)));

  igp->checksum=htons(chk);
return q;
}

Packet *
ICMP6Checksum::simple_action(Packet *p_in)
{
  Packet *p=addchecksum(p_in);
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ICMP6Checksum)
ELEMENT_MT_SAFE(ICMP6Checksum)
