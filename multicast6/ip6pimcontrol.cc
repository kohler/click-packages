/*
 * IP6PIMControl.{cc,hh} -- PIM processing element
 * Martin Hoffmann
 *
 * Copyright (c) 2005 University of Bristol, University of Hanover
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
#include <click/router.hh>
#include <click/confparse.hh>
#include "ip6pimcontrol.hh"
#include "debug.hh"
#include "ip6protocoldefinitions.hh"
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>


IP6PIMControl::IP6PIMControl(): _timer(this)
{
}

IP6PIMControl::~IP6PIMControl()
{
}

int IP6PIMControl::initialize(ErrorHandler *errh)
{
  _timer.initialize(this);
  _timer.schedule_after_msec(1000);
  source_connected=false;
  return 0;
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get PIM enabled interfaces                                                   *
 *                                                                                         *
 *******************************************************************************************/
int
IP6PIMControl::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("wrong number of arguments; expected 'IP6PIMControl(PIMForwardingTable element)'");

  // get PIMForwardingTable element
  Element *e = cp_element(conf[0], this, errh);
  if (!e) {
    return -1;
  }
  else {
	PIMTable = (IP6PIMForwardingTable *)e->cast("IP6PIMForwardingTable");
	return 0;
  }
}

void 
IP6PIMControl::generatejoinprune(IP6Address group, IP6Address source, bool join)
{  
  debug_msg("pimcontrol generatejoinprune");
  WritablePacket *q = 0;

  click_ip6 *nip;
  Pim_Header *header;
  Pim_IPv6_Join_Prune *joinprune;
  Pim_IPv6_Group_Record *grouprecord;
  Pim_IPv6_Source *sender;
  Pim_IPv6_Unicast *unicastneighbor;


  q = Packet::make(sizeof(*nip)+sizeof(*header)+sizeof(*unicastneighbor)+sizeof(*joinprune)+sizeof(*grouprecord)+sizeof(*sender));

  nip = reinterpret_cast<click_ip6 *>(q->data());
  header=(Pim_Header *) (q->data() + sizeof(*nip));
  unicastneighbor=(Pim_IPv6_Unicast *)((char *)header + sizeof(*header));
  joinprune=(Pim_IPv6_Join_Prune *)((char *)unicastneighbor + sizeof(*unicastneighbor));
  grouprecord=(Pim_IPv6_Group_Record *)((char *)joinprune + sizeof(*joinprune));
  sender=(Pim_IPv6_Source *)((char *)grouprecord + sizeof(*grouprecord));

  nip->ip6_flow = 0;
  nip->ip6_v = 6;
  nip->ip6_nxt = 0x67;
  nip->ip6_hlim = 0x02;
  nip->ip6_src = IP6Address("0::");

  // ip_src is set by the FixIPSource element
 
  // send to sender address provided in PIM join message, i.e. downstream
  // nip->ip_dst = IP6Address(source);
  //  debug_msg("ipaddress source %x", IP6Address(source));
  // nip->ip_dst = IP6Address(source);
 
  // ** working
  nip->ip6_dst = IP6Address(source);
  // ** debug
  //  nip->ip6_dst = IP6Address("FF02::d");
  //  SET_DST_IP6_ANNO(q, IP6Address(source));
  SET_DST_IP6_ANNO(q, IP6Address(source));
  nip->ip6_plen=htons(sizeof(*header)+sizeof(*unicastneighbor)+sizeof(*joinprune)+sizeof(*grouprecord)+sizeof(*sender));

  header->ver_type=0x23;
  header->checksum=0x0000;
  header->reserved=0x0;
  unicastneighbor->addr_family=2;
  unicastneighbor->encoding_type=0;
  // this address has to be fixed on the outgoing interface

  // unicastneighbor->addr=IP6Address("0::"); // the upstreamneighbor address is set in the fixpimsource element

  joinprune->reserved=0;
  joinprune->no_of_groups=1;
  joinprune->holdtime=0xffff; // 0xffff does instruct next router not to ask again

  grouprecord->addr_family=2;
  grouprecord->encoding_type=0;
  grouprecord->rsv=0;
  grouprecord->mask_len=128;
  grouprecord->addr=(IP6Address(group));

  grouprecord->addr=(IP6Address(group));
  if(join) {
	grouprecord->no_of_joined_sources=htons(1);
	grouprecord->no_of_pruned_sources=0;
  }
  else {
	grouprecord->no_of_joined_sources=0;
	grouprecord->no_of_pruned_sources=htons(1);
  }

  sender->addr_family=2;
  sender->encoding_type=0;
  sender->swr=4;
  sender->mask_len=128;
  //  sender->addr=htonl(IP6Address(source)); (X)
  sender->addr=IP6Address(source);
 
  q->set_ip6_header(nip, 40); // (XXXX)

  q->timestamp_anno().set_now();
  //  SET_FIX_IP6_SRC_ANNO(q, true);

  output(0).push(q);
}


void
IP6PIMControl::generate_hello()
{
  // debug_msg("Pim_RPT generate hello");
  Pim_Header* p_header;
  Pim_Holdtime* p_options;
  //  hopbyhopheader* hopbyhop;

  WritablePacket *q;

  click_ip6 *nip;

  q = Packet::make(sizeof(*nip)+sizeof(*p_header)+sizeof(*p_options));

  nip = reinterpret_cast<click_ip6 *>(q->data());

  //  hopbyhop=(hopbyhopheader *)(q->data() + sizeof(*nip));
  p_header=(Pim_Header *)(char *)(q->data() + sizeof(*nip)); //hopbyhop + sizeof(*hopbyhop);
  p_options=(Pim_Holdtime *)((char *)p_header + sizeof(*p_header));

  //---------------

  nip->ip6_flow = 0;
  nip->ip6_v = 6;
  nip->ip6_nxt = 0x67;
  nip->ip6_src = IP6Address("0::0");
  nip->ip6_plen=htons(sizeof(*p_header)+sizeof(*p_options));
  SET_DST_IP6_ANNO(q, IP6Address("ff02::d")); //PIM all router address

  nip->ip6_hlim=0x01; //kill at next router but let pass through this one
  nip->ip6_dst = IP6Address("ff02::d");
  //----------------

  //  hopbyhop->type=0x67;  //MLD router alert
  //  hopbyhop->length=0;
  //  hopbyhop->parameter=0x0502;

  p_header->ver_type=0x20;
  p_header->reserved=0x00;
  p_header->checksum=0x0000;

  p_options->type=htons(0x01);
  p_options->len=htons(0x02);
  p_options->value=0xFFFF; 

  //  q->set_ip_header(nip, nip->ip_hl << 2);
  SET_DST_IP6_ANNO(q, IP6Address(nip->ip6_dst));
  // q->timestamp_anno().set_now();
  //  SET_FIX_IP_SRC_ANNO(q, true);

  output(0).push(q);
}

void
IP6PIMControl::run_timer(Timer *)
{
  //  generatejoin(IP6Address("232.2.2.2"), IP6Address("192.168.20.2"));
  
  generate_hello();
  _timer.reschedule_after_msec(3000);
}


bool
IP6PIMControl::noPIMreceivers(IP6Address group, IP6Address source)
{
  debug_msg("checking whether there are PIM receivers connected... embedded rp addr is");

  IP6Address knut=extract_rp(group);

 click_chatter("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", (unsigned char)(* knut.data() + 0),(unsigned char)(* (knut.data() + 1)), (unsigned char)(* (knut.data() + 2)), (unsigned char)(* (knut.data() + 3)),(unsigned char)(* (knut.data() + 4)), (unsigned char)(* (knut.data() + 5)), (unsigned char)(* (knut.data() + 6)), (unsigned char)(* (knut.data() + 7)), (unsigned char)(* (knut.data() + 8)), (unsigned char)(* (knut.data() + 9)), (unsigned char)(* (knut.data() + 10)), (unsigned char)(* (knut.data() + 11)), (unsigned char)(* (knut.data() + 12)), (unsigned char)(* (knut.data() + 13)), (unsigned char)(* (knut.data() + 14)), (unsigned char)(* (knut.data() + 15))  ); 

  return PIMTable->getPIMreceivers(extract_rp(group), group);
}

IP6Address 
IP6PIMControl::extract_rp(IP6Address group)
{
  struct group_address
  {
    unsigned char plen: 8;
    unsigned char RIID: 4;
    unsigned int extra_bits: 20;
    unsigned int np1: 32;
    unsigned int np2: 32;
    unsigned int groupID: 32;
  };
  
  IP6Address rp;
  rp=IP6Address("::");

  unsigned int gbuf[4], rbuf[4]; // buffer for generation of RP address

  memcpy(&gbuf, group.data(), 16);

  for (unsigned int i=0; i<4; i++) {
    gbuf[i]=ntohl(gbuf[i]);
  }

  group_address *group_addr=(group_address *) (void *) &gbuf;

  // debug_msg("MLD: extrabits %x", group_addr->extra_bits);
  // debug_msg("MLD: RIID %x", group_addr->RIID);
  // debug_msg("MLD: plen %x", group_addr->plen);

  if(group_addr->plen <= 32) {
    group_addr->np2=0;
    group_addr->np1=htonl((ntohl(group_addr->np1) >> (32-group_addr->plen)));
    group_addr->np1=htonl((ntohl(group_addr->np1) << (32-group_addr->plen)));
  }
  if(group_addr->plen > 32) {
    group_addr->np2=htonl((ntohl(group_addr->np2) << (64-group_addr->plen)));
    group_addr->np2=htonl((ntohl(group_addr->np2) >> (64-group_addr->plen)));
  }

  memcpy(&rbuf, (((char *) group_addr) + 4), 8); // copy complete network prefix
  char _RIID = group_addr->RIID;

  for (unsigned int i=0; i<4; i++) {
    //debug_msg("MLD: abuf0 %x", abuf[0]);
    rbuf[i]=htonl(rbuf[i]);
  }
  memcpy( (((char *) &rbuf) + 15), &_RIID, 1);

  memcpy(rp.data(), &rbuf, 16);

  return rp;
}

EXPORT_ELEMENT(IP6PIMControl)
