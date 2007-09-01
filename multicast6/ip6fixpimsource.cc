/*
 * ip6fixpimsource.{cc,hh} -- element sets outgoing interface IP address ( = upstream neighbor)
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
#include "ip6fixpimsource.hh"
#include "ip6protocoldefinitions.hh"
#include "ip6pimforwardingtable.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/confparse.hh>


CLICK_DECLS

IP6FixPIMSource::IP6FixPIMSource()
{
}

IP6FixPIMSource::~IP6FixPIMSource()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get interfaces IP address here                                               *
 *                                                                                         *
 *******************************************************************************************/
int
IP6FixPIMSource::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 2)
    return errh->error("FIXPIMSOURCE wrong number of arguments;expected: 'IP6FixPIMSource(Address, PIMForwardingTable element)' ");
  
  // get outgoing interface's address
  if (!cp_ip6_address(conf[0], (unsigned char *) &interfaceaddr)) { 
	return -1;
  }

  Element *e = cp_element(conf[1], this, errh);
  if (!e) {
    return -1;
  }
  else {
	PIMTable = (IP6PIMForwardingTable *)e->cast("IP6PIMForwardingTable");
  }
  return 0;
}


// This is a rather short version, you might want to extend this element and implement some more
// functionality. It does not check whether it is feeded with proper icmpv6 messages or not.
// You have to make sure only ICMPv6 packets are handed to this element because it does not check the packet it receives.
WritablePacket *
IP6FixPIMSource::fixpimsource(Packet *p_in)
{
  WritablePacket *q = p_in->uniqueify();
  const click_ip6 *ip = reinterpret_cast <const click_ip6 *>( q->data());
  //  click_ip6 *ip = reinterpret_cast <click_ip6 *>( q->data());
  char* datapoint=(char *) q->data();
  PIMMessage *pimmessage=(PIMMessage *) (q->data() + sizeof(click_ip6));

  // packets containing PIM Join/Prune commands get their checksum and the outgoing interfaces IP address here

  //  void * neighbor_addr = PIMTable->get_upstreamneighbor(interfaceaddr.addr())

  click_in6_addr a = PIMTable->get_upstreamneighbor(IP6Address(interfaceaddr)); 
  if(ip->ip6_nxt==0x67)
	{
	  if((pimmessage->ver_type==0x23 || pimmessage->ver_type==0x13) ) {
	     // && (pimmessage->checksum==0)){
	    unsigned int buf[4];
	    for(unsigned int i=0; i<4; i++) {
	      memcpy((((int *) &buf) + i), (((int *) &a) +i), 4);
	      //	      buf[i]=htonl(buf[i]);
	    }
	    memcpy(&pimmessage->uaddr, &buf, 16); //interfaceaddr.addr();
	  }

	  /*	  unsigned int sum;
	  sum=0;
	  int count;
	  count=q->length()-sizeof(*ip);
	  click_chatter("count: %d", count); */

	  unsigned short *datapoint=(unsigned short *)pimmessage; //q->data()+(sizeof(*ip)>>1);
	  pimmessage->checksum=htons(in6_cksum(&ip->ip6_src, &ip->ip6_dst, ip->ip6_plen, 0x67, 0x00, (unsigned char *)datapoint, ip->ip6_plen));	  

		/*	  while(count > 1) {
	  sum += *datapoint++;
	  count -= 2;
	  }
	  
	  if(count > 0) sum += *(unsigned char *)datapoint;
	  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	  
	  pimmessage->checksum=~sum; */
	}

  return q;
}

Packet *
IP6FixPIMSource::simple_action(Packet *p_in)
{
  Packet *p=fixpimsource(p_in);
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6FixPIMSource)
ELEMENT_MT_SAFE(IP6FixPIMSource)
