/*
 * PIMControl.{cc,hh} -- PIM processing element
 * Martin Hoffmann
 *
 * Copyright (c) 2005, 2006 University of Bristol, University of Hanover
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
#include "pimcontrol.hh"
#include <click/error.hh>
#include <click/packet_anno.hh>
#include "debug.hh"

PIMControl::PIMControl(): _timer(this)
{
}

PIMControl::~PIMControl()
{
}

int PIMControl::initialize(ErrorHandler *errh)
{
  _timer.initialize(this);
  _timer.schedule_after_msec(1000);
  return 0;
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get PIM enabled interfaces                                                   *
 *                                                                                         *
 *******************************************************************************************/
int
PIMControl::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("wrong number of arguments; expected 'PIMControl(PIMForwardingTable element)'");

  // get PIMForwardingTable element
  Element *e = cp_element(conf[0], this, errh);
  if (!e) {
    return -1;
  }
  else {
	PIMTable = (PIMForwardingTable *)e->cast("PIMForwardingTable");
	return 0;
  }
}

void
PIMControl::join(IPAddress group, IPAddress source)
{
  debug_msg("sending pim join message");
  if(!source_connected) {
	generatejoin(group, source, true);
  }
}


void
PIMControl::prune(IPAddress group, IPAddress source)
{
  debug_msg("sending pim prune message");
  if(!source_connected) {
	generatejoin(group, source, false);
  }
}

void 
PIMControl::generatejoin(IPAddress group, IPAddress source, bool join)
{
  
  debug_msg("generatejoin PIM");
  WritablePacket *q = 0;

  click_ip *nip;
  IPoptions* ipoptions; // make sure routers open this packet
  Pim_Header *header;
  Pim_IPv4_Join_Prune *joinprune;
  Pim_IPv4_Group_Record *grouprecord;
  Pim_IPv4_Source *sender;
  Pim_IPv4_Unicast *unicastneighbor;

  q = Packet::make(sizeof(*nip) +
				   sizeof(*ipoptions) +
				   sizeof(*header) +
				   sizeof(*unicastneighbor) +
				   sizeof(*joinprune) +
				   sizeof(*grouprecord) + 
				   sizeof(*sender));


  nip = reinterpret_cast<click_ip *>(q->data());

  ipoptions=(IPoptions*)(q->data() + sizeof(*nip));
  header=(Pim_Header *)((char *)ipoptions + sizeof(*ipoptions));
  unicastneighbor=(Pim_IPv4_Unicast *)((char *)header + sizeof(*header));
  joinprune=(Pim_IPv4_Join_Prune *)((char *)unicastneighbor + sizeof(*unicastneighbor));
  grouprecord=(Pim_IPv4_Group_Record *)((char *)joinprune + sizeof(*joinprune));
  sender=(Pim_IPv4_Source *)((char *)grouprecord + sizeof(*grouprecord));


  nip->ip_v = 4;
  nip->ip_tos = 0;		
  nip->ip_id = 0x5ff4; htons(0x67);
  nip->ip_off = 0;
  nip->ip_tos =0xc0;
  nip->ip_ttl = 2;
  nip->ip_p = 0x67;
  nip->ip_sum = 0;
  nip->ip_dst = IPAddress("224.0.0.13"); // IPAddress(htonl(source));
  nip->ip_hl = 6; // (sizeof(*nip) >> 2) + 1; // +1 for ipotions
  nip->ip_len=htons(q->length());

  ipoptions->data[0]=0x94;
  ipoptions->data[1]=0x04;
  ipoptions->data[2]=0x00;
  ipoptions->data[3]=0x00;

  header->ver_type=0x23;
  header->checksum=0x0;
  header->reserved=0x0;

  unicastneighbor->addr_family=1;
  unicastneighbor->encoding_type=0;
  //  click_chatter("pimctl got upstream-neighbor from pimtable: %x",IPAddress( PIMTable->get_upstreamneighbor(group, source)));
  //  memcpy((void *)&unicastneighbor->addr, &buf, 4);
  // this address is fixed on the outgoing interface

  joinprune->reserved=0;
  joinprune->no_of_groups=1;
  joinprune->holdtime=0xffff; // 0xffff does instruct next router not to ask again

  grouprecord->addr_family=1;
  grouprecord->encoding_type=0;
  grouprecord->swr=4;
  grouprecord->mask_len=32;
  grouprecord->addr=IPAddress(group);
  
  if(join) {
	grouprecord->no_of_joined_sources=htons(1);
	grouprecord->no_of_pruned_sources=0;
  }
  else {
	grouprecord->no_of_joined_sources=0;
	grouprecord->no_of_pruned_sources=htons(1);
  }

  sender->addr_family=1;
  sender->encoding_type=0;
  sender->swr=4;
  sender->mask_len=32;
  sender->addr=htonl(IPAddress(source));
  
  q->set_ip_header(nip, nip->ip_hl << 2);
  q->set_dst_ip_anno((IPAddress(htonl(source))));
  q->timestamp_anno().set_now();
  SET_FIX_IP_SRC_ANNO(q, true);

  output(1).push(q); 
}

void
PIMControl::generate_hello()
{
  debug_msg("PimControl generates hello");
  Pim_Header* p_header;
  Pim_Options* holdtime;
  Pim_longOptions* prunedelay;
  Pim_longOptions* priority;
  Pim_longOptions* gid;
  IPoptions* ipoptions;

  WritablePacket *q;

  click_ip *nip;

  q = Packet::make(sizeof(*nip) +
				   sizeof(*ipoptions) +
				   sizeof(*p_header) +
				   sizeof(*holdtime) +
				   sizeof(*prunedelay) +
				   sizeof(*gid) +
				   sizeof(*priority));

  nip = reinterpret_cast<click_ip *>(q->data());
  ipoptions=(IPoptions*)(q->data() + sizeof(*nip));
  p_header=(Pim_Header *)((char *)ipoptions + sizeof(*ipoptions));
  holdtime=(Pim_Options *)((char *)p_header + sizeof(*p_header));
  prunedelay=(Pim_longOptions *)((char *)holdtime + sizeof(*holdtime));
  priority=(Pim_longOptions *)((char *)prunedelay + sizeof(*prunedelay));
  gid=(Pim_longOptions *)((char *)priority + sizeof(*priority));

  ipoptions->data[0]=0x94;
  ipoptions->data[1]=0x04;
  ipoptions->data[2]=0x00;
  ipoptions->data[3]=0x00;

  nip->ip_v = 4;
  nip->ip_tos = 0;		
  nip->ip_id = 0x5ff4; htons(0x67);
  nip->ip_off = 0;
  nip->ip_tos =0xc0;
  nip->ip_ttl = 1;
  nip->ip_p = 0x67;
  nip->ip_sum = 0;
  nip->ip_dst = IPAddress("224.0.0.13"); // XXX
  nip->ip_hl = 6; // (sizeof(*nip) >> 2) + 1; // + 1 for ipotions
  nip->ip_len=htons(q->length());

  p_header->ver_type=0x20;
  p_header->reserved=0x00;
  p_header->checksum=0x0000;

  holdtime->type=htons(0x01);
  holdtime->len=htons(0x02);
  holdtime->value=htons(0x69); 

  prunedelay->type=htons(2);
  prunedelay->len=htons(0x04);
  prunedelay->value=htonl(0x01f409c4); 


  priority->type=htons(19);
  priority->len=htons(0x04);
  priority->value=htonl(0x2); 

  gid->type=htons(20);
  gid->len=htons(0x04);
  gid->value=htons(1033457501); 

  q->set_ip_header(nip, nip->ip_hl << 2);
  q->set_dst_ip_anno(IPAddress(nip->ip_dst));
  q->timestamp_anno().set_now();
  SET_FIX_IP_SRC_ANNO(q, true);

  output(1).push(q);
}

void
PIMControl::run_timer(Timer *)
{
  //  generatejoin(IPAddress("232.2.2.2"), IPAddress("192.168.20.2"));
  generate_hello();
  _timer.reschedule_after_msec(3000); // XXX
}

bool
PIMControl::noPIMreceivers(IPAddress group, IPAddress source)
{
  debug_msg("checking whether there are PIM receivers connected...");
  return PIMTable->getPIMreceivers(source, group);
}

EXPORT_ELEMENT(PIMControl)
