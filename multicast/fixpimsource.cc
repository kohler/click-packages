/*
 * fixpimsource.{cc,hh} -- element sets outgoing interface IP address ( = upstream neighbor)
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
#include "fixpimsource.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/confparse.hh>


CLICK_DECLS

FixPIMSource::FixPIMSource()
{
}

FixPIMSource::~FixPIMSource()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get interfaces IP address here                                               *
 *                                                                                         *
 *******************************************************************************************/
int
FixPIMSource::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 2)
    return errh->error("wrong number of arguments; expected 'FixPIMSource(Address, PIMForwardingTable element)'");
  
  // get PIMForwardingTable element
  if (!cp_ip_address(conf[0], &interfaceaddr)) { 
	return -1;
  }

  Element *e = cp_element(conf[1], this, errh);
  if (!e) {
    return -1;
  }
  else {
	PIMTable = (PIMForwardingTable *)e->cast("PIMForwardingTable");
  }
  return 0;
}


// This is a rather short version, you might want to extend this element and implement some more
// functionality. It does not check whether it is feeded with proper icmpv6 messages or not.
// You have to make sure only ICMPv6 packets are handed to this element because it does not check the packet it receives.
WritablePacket *
FixPIMSource::fixpimsource(Packet *p_in)
{
  WritablePacket *q = p_in->uniqueify();
  const click_ip *ip = reinterpret_cast <const click_ip *>( q->data());
  char* datapoint=(char *) q->data();
  PIMMessage *pimmessage=(PIMMessage *) (q->data() + ((ip->ip_hl)<<2));

  // packets containing PIM Join/Prune commands get their checksum and the outgoing interfaces IP address here

  unsigned int a=interfaceaddr.addr();
  if(ip->ip_p==0x67)
	{
	  if((pimmessage->ver_type==0x23 || pimmessage->ver_type==0x13) && (pimmessage->checksum==0))
		{
		  uint32_t buf=IPAddress(PIMTable->get_upstreamneighbor(interfaceaddr.addr()));
		  memcpy(&(pimmessage->uaddr), &buf, 4); //interfaceaddr.addr();
	  }
	  
	  unsigned int sum;
	  sum=0;
	  int count;
	  count=q->length()-(ip->ip_hl*4);
	  
	  unsigned short *datapoint=(unsigned short *)q->data()+(ip->ip_hl*2);
	  
	  while(count > 1) {
	  sum += *datapoint++;
	  count -= 2;
	  }
	  
	  if(count > 0) sum += *(unsigned char *)datapoint;
	  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	  
	  pimmessage->checksum=~sum; 
	}

  return q;
}

Packet *
FixPIMSource::simple_action(Packet *p_in)
{
  //  click_chatter("packet coming through icmp6checksum");

  //  return p_in;
  Packet *p=fixpimsource(p_in);
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FixPIMSource)
ELEMENT_MT_SAFE(FixPIMSource)
