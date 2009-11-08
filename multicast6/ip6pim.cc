/*
 * IP6PIM.{cc,hh} -- PIM processing element
 * Martin Hoffmann
 *
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
#include <clicknet/ip6.h>
#include <click/router.hh>
#include "ip6pim.hh"
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/ip6address.hh>
#include <click/confparse.hh>
#include "debug.hh"

IP6PIM::IP6PIM()
{
}

IP6PIM::~IP6PIM()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get PIM interface and IP6PIMForwardingTable element                          *
 *                                                                                         *
 *******************************************************************************************/
int
IP6PIM::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 4)
    return errh->error("wrong number of arguments; expected 'PIM_SPT(IP6MulticastTable IP6PIMForwardingTable IP6PIMControl interface)'");

  // get IP6MulticastTable element
  Element *e0 = cp_element(conf[0], this, errh);
  if (!e0) {
    debug_msg("cp_element failed");
	return -1;
  }
  else {
	//    debug_msg("cp_element succesful");
	MulticastTable = (IP6MulticastTable *)e0->cast("IP6MulticastTable");
  }


  // get IP6PIMForwardingTable element
  Element *e = cp_element(conf[1], this, errh);
  if (!e) {
    debug_msg("IP6PIM: cp_element failed");
	return -1;
  }
  else {
	PIMTable = (IP6PIMForwardingTable *)e->cast("IP6PIMForwardingTable");
  }

  // get PIMControl element
  Element *e2 = cp_element(conf[2], this, errh);
  if (!e2) {
    debug_msg("IP6PIM: cp_element failed");
	return -1;
  }
  else {
	PIMSpt = (IP6PIMControl *)e2->cast("IP6PIMControl");
  }

  if (!cp_ip6_address(conf[3], (unsigned char *)&interface)) { 
	debug_msg("IP6PIM: cp_ip6_address failed!");
	return errh->error("expects IP6ADDRESS -a ");
  }
 
  return 0;
}

/*******************************************************************************************
 *                                                                                         *
 * simpleaction: every arriving packet is examined here, hellos and join/prune messages    *
 *               are processed                                                             *
 *                                                                                         *
 *******************************************************************************************/
void IP6PIM::push(int port, Packet *p)

{
  click_in6_addr temp_addr;
  unsigned short mysum;

  const click_ip6 *ip = (click_ip6 *)p->data();

  Pim_Header *pheader;
  Pim_Options *options;

  unsigned int no_of_sources;
  unsigned int no_of_groups;
  unsigned int pregrouplen; // length of preceding grouprecord
  pregrouplen=0;

  Pim_IPv6_Join_Prune *joinprune;
  Pim_IPv6_Group_Record *grouprecord;
  Pim_IPv6_Source *sender;
  Pim_IPv6_Unicast *unicastneighbor;

  pheader=(Pim_Header *) (p->data() + sizeof(*ip));

  if((ip->ip6_nxt)==103) {     // process PIM messages only

	switch(pheader->ver_type) 
	  {
	  case 0x10:
	  case 0x20:
		//	debug_msg("IP6PIM: PIM hello message arrived");
		options=(Pim_Options *)((char *)pheader + sizeof(*pheader));
		if (in6_cksum(&ip->ip6_src, 
			      &ip->ip6_dst,
			      ip->ip6_plen,
			      0x67,
			      0x00,
			      (unsigned char *)pheader,
			      ip->ip6_plen) != 0) {
		  debug_msg("IP6PIM: PIM checksum not correct but processing hello anyway!");
		}

		PIMTable->addinterface(IP6Address(interface), IP6Address(ip->ip6_src));
		break;
	  case 0x13:
	  case 0x23:
		debug_msg("IP6PIM: PIM got joinprune");
		if (in6_cksum(&ip->ip6_src, 
			      &ip->ip6_dst,
			      ip->ip6_plen,
			      0x67,
			      0x00,
			      (unsigned char *)pheader,
			      ip->ip6_plen) != 0) {
		  debug_msg("IP6PIM: PIM checksum not correct but processing join/prune message anyway!");
		}
		unicastneighbor=(Pim_IPv6_Unicast *)((char *)pheader + sizeof(*pheader));

		joinprune=(Pim_IPv6_Join_Prune *)((char *)unicastneighbor + sizeof(*unicastneighbor));
		memcpy(&temp_addr, &(unicastneighbor->addr), 4);

		for(no_of_groups=0; no_of_groups<joinprune->no_of_groups; no_of_groups++)
		  {
			grouprecord=(Pim_IPv6_Group_Record *)((char *)joinprune +
							      sizeof(*joinprune) +
							      pregrouplen);
			for(no_of_sources=0; no_of_sources<ntohs(grouprecord->no_of_joined_sources) ;++no_of_sources) {
			  sender=(Pim_IPv6_Source *)((char *)grouprecord + sizeof(*grouprecord));
			  PIMTable->addgroup(IP6Address(interface),
					     IP6Address(grouprecord->addr),
					     IP6Address(sender->addr),
					     IP6Address(temp_addr));
			  pregrouplen += sizeof(*sender);

			  if ( IP6Address(grouprecord->addr).matches_prefix(IP6Address("FF70::0"),
								IP6Address("FFF0::0")) )     {
			   
			    PIMSpt->generatejoinprune( IP6Address(grouprecord->addr),
						       IP6Address(extract_rp(IP6Address(grouprecord->addr))),
						       true);
			    }
										   

			  else PIMSpt->generatejoinprune( IP6Address(grouprecord->addr),
						     IP6Address(sender->addr),
						     true);
			}
			for(no_of_sources=0; no_of_sources<ntohs(grouprecord->no_of_pruned_sources); ++no_of_sources) {
			  sender=(Pim_IPv6_Source *)((char *)grouprecord +
						     sizeof(*grouprecord));
			  PIMTable->delgroup(IP6Address(interface),
					     IP6Address(grouprecord->addr),
					     IP6Address(sender->addr),
					     IP6Address(temp_addr));
			  pregrouplen += sizeof(*sender);


			  if ( IP6Address(grouprecord->addr).matches_prefix(IP6Address("FF70::0"),
								IP6Address("FFF0::0")) )     {


			    if(MulticastTable->getMLDreceivers(extract_rp(IP6Address(grouprecord->addr)), IP6Address(grouprecord->addr))==true) {


				PIMSpt->generatejoinprune( IP6Address(grouprecord->addr),
							   IP6Address(extract_rp(IP6Address(grouprecord->addr))),
										   false);
										   }
			  }
			  else PIMSpt->generatejoinprune( IP6Address(grouprecord->addr),
						     IP6Address(sender->addr), 
						     false);
			}
			pregrouplen += sizeof(*grouprecord);
		  }
		break;
	  default:
		debug_msg("IP6PIM: PIM does not know this type of message!");
	  }

	output(1).push(p);  
  }
  else {
    //	debug_msg("IP6PIM: no PIM message");
	output(0).push(p);  
  }  
}

IP6Address 
IP6PIM::extract_rp(IP6Address group)
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
    rbuf[i]=htonl(rbuf[i]);
  }
  memcpy( (((char *) &rbuf) + 15), &_RIID, 1);

  memcpy(rp.data(), &rbuf, 16);

  return rp;
}

EXPORT_ELEMENT(IP6PIM)
