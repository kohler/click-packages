/*
 * mcastetherencap.{cc,hh} -- encapsulates packet in Ethernet header
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2006 University of Bristol, University of Hanover
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
#include "mcastetherencap.hh"
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

IPMulticastEtherEncap::IPMulticastEtherEncap()
{
}

IPMulticastEtherEncap::~IPMulticastEtherEncap()
{
}

int
IPMulticastEtherEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
  unsigned etht;
  if (cp_va_kparse(conf, this, errh,
		   "ETHTYPE", cpkP+cpkM, cpUnsigned, &etht,
		   "SRCETH", cpkP+cpkM, cpEthernetAddress, &_ethh.ether_shost,
		   cpEnd) < 0)
    return -1;
  if (etht > 0xFFFF)
    return errh->error("argument 1 (Ethernet encapsulation type) must be <= 0xFFFF");
  _ethh.ether_type = htons(etht);
  return 0;
}

Packet *
IPMulticastEtherEncap::smaction(Packet *p)
{
  if (WritablePacket *q = p->push_mac_header(14)) {
	uint8_t ip_data[4];
	uint32_t buf1; // to change byteorder


	//get destination IP address
	memcpy(&buf1, ((char*)(q->data()))+30, 4);
	buf1=htonl(buf1);
	memcpy(&ip_data, ((char*)(&buf1)), 4);

	ip_data[2]=ip_data[2] >> 1;
	uint8_t ea_data[6];

	// set multicast OUI
	ea_data[0]=0x01;
	ea_data[1]=0x00;
	ea_data[2]=0x5E;

   
	ea_data[3]=(ip_data[2]<<1);
	ea_data[4]=ip_data[1];
	ea_data[5]=ip_data[0];

	memcpy(&_ethh.ether_dhost, &ea_data[0], 6);
    memcpy(q->data(), &_ethh, 14);
    return q;
  } else
    return 0;
}

void
IPMulticastEtherEncap::push(int, Packet *p)
{
  if (Packet *q = smaction(p))
    output(0).push(q);
}

Packet *
IPMulticastEtherEncap::pull(int)
{
  if (Packet *p = input(0).pull())
    return smaction(p);
  else
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IPMulticastEtherEncap)
