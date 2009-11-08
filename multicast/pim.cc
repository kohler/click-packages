/*
 * PIM.{cc,hh} -- PIM processing element
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
#include <click/router.hh>
#include "pim.hh"
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include "debug.hh"

PIM::PIM()
{
}

PIM::~PIM()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get PIM interface and PIMForwardingTable element                             *
 *                                                                                         *
 *******************************************************************************************/
int
PIM::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 4)
    return errh->error("wrong number of arguments; expected 'PIM_SPT(IPMulticastTable PIMForwardingTable PIM_SPT interface)'");


  // get IPMulticastTable element
  Element *e0 = cp_element(conf[0], this, errh);
  if (!e0) {
    debug_msg("cp_element failed");
	return -1;
  }
  else {
	//    debug_msg("cp_element succesful");
	MulticastTable = (IPMulticastTable *)e0->cast("IPMulticastTable");
  }

  // get PIMForwardingTable element
  Element *e = cp_element(conf[1], this, errh);
  if (!e) {
    debug_msg("cp_element failed");
	return -1;
  }
  else {
	//    debug_msg("cp_element succesful");
	PIMTable = (PIMForwardingTable *)e->cast("PIMForwardingTable");
  }

  // get PIMctl element
  Element *e2 = cp_element(conf[2], this, errh);
  if (!e2) {
    debug_msg("cp_element failed");
	return -1;
  }
  else {
	//    debug_msg("cp_element succesful");
	PIMSpt = (PIMControl *)e2->cast("PIMControl");
  }


  IPAddress a;
  if (!cp_ip_address(conf[3], &a)) { 
	debug_msg("cp_ip_address failed!");
	return errh->error("expects IPADDRESS -a ");
  }
  else {
	interface=a;
	const unsigned char *p = interface.data();
	debug_msg("PIM configured interface address: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);
  }  
  return 0;
}

/*******************************************************************************************
 *                                                                                         *
 * simpleaction: each arriving packet is examined here, hellos and join/prune messages     *
 *               are processed                                                             *
 *                                                                                         *
 *******************************************************************************************/
void PIM::push(int port, Packet *p)

{
  IPAddress temp_addr;
  unsigned short mysum;

  const click_ip *ip = p->ip_header();

  Pim_Header *pheader;
  Pim_Options *options;

  const unsigned char *pt;

  unsigned int no_of_sources;
  unsigned int no_of_groups;
  unsigned int pregrouplen; // length of preceding grouprecord
  pregrouplen=0;

  Pim_IPv4_Join_Prune *joinprune;
  Pim_IPv4_Group_Record *grouprecord;
  Pim_IPv4_Source *sender;
  Pim_IPv4_Unicast *unicastneighbor;

  pheader=(Pim_Header *) (p->data() + ((ip->ip_hl)<<2) ); // sizeof(*ip));

  if((ip->ip_p)==103) {     // process PIM messages only

	switch(pheader->ver_type) 
	  {
	  case 0x10:
	  case 0x20:
		debug_msg("PIM hello message arrived");
		options=(Pim_Options *)((char *)pheader + sizeof(*pheader));
		
		if(click_in_cksum((unsigned char*)(p->data() + (ip->ip_hl*4)), 
						  ntohs(ip->ip_len)-ip->ip_hl*4 ) != 0) {
		  click_chatter("PIM checksum not correct but processing join/prune message anyway!");
		}

		(pt) = interface.data();
		
		debug_msg("Added interface address: %d.%d.%d.%d", pt[0], pt[1], pt[2], pt[3]);
		PIMTable->addinterface(IPAddress(interface), IPAddress(ip->ip_src));
		break;
	  case 0x13:
	  case 0x23:
		debug_msg("PIM got joinprune");
		if(click_in_cksum((unsigned char*)(p->data() + (ip->ip_hl*4)), 
						  ntohs(ip->ip_len)-ip->ip_hl*4 ) != 0) {
		  debug_msg("PIM checksum not correct but processing join/prune message anyway!");
		}

		unicastneighbor=(Pim_IPv4_Unicast *)((char *)pheader + sizeof(*pheader));
		joinprune=(Pim_IPv4_Join_Prune *)((char *)unicastneighbor + sizeof(*unicastneighbor));
		memcpy(&temp_addr, &(unicastneighbor->addr), 4);

		for(no_of_groups=0; no_of_groups<(joinprune->no_of_groups); no_of_groups++)
		  {
			grouprecord=(Pim_IPv4_Group_Record *)((char *)joinprune
												  + sizeof(*joinprune)
												  + pregrouplen);

			for(no_of_sources=0; no_of_sources<ntohs(grouprecord->no_of_joined_sources) ;++no_of_sources) {
			  sender=(Pim_IPv4_Source *)((char *)grouprecord + sizeof(*grouprecord));
			  PIMTable->addgroup(IPAddress(interface),
								 IPAddress(grouprecord->addr),
								 //			   	 IPAddress(ntohl(grouprecord->addr)),
								 IPAddress(sender->addr),
								 IPAddress(temp_addr));

			  // do not trust big/little endian conversion?
			  debug_msg("neighboraddr is %x-%x", 
						ntohs(unicastneighbor->addr[0]), 
						ntohs(unicastneighbor->addr[1]));

			  debug_msg("copy of neighboraddr is %x", ntohl(temp_addr.addr()));
			  

			  pregrouplen += sizeof(*sender);
			  PIMSpt->generatejoin( IPAddress((IPAddress(grouprecord->addr))),
									IPAddress(htonl(IPAddress(sender->addr))),
									true);
			}
			for(no_of_sources=0; no_of_sources<ntohs(grouprecord->no_of_pruned_sources) ;++no_of_sources) {
			  sender=(Pim_IPv4_Source *)((char *)grouprecord + sizeof(*grouprecord));
			  PIMTable->delgroup(IPAddress(interface), 
								 IPAddress(grouprecord->addr),
								 IPAddress(sender->addr),
								 IPAddress(temp_addr));
			  pregrouplen += sizeof(*sender);
			  if(MulticastTable->getIGMPreceivers((sender->addr), grouprecord->addr)) {
				PIMSpt->generatejoin( IPAddress(grouprecord->addr),
									  IPAddress(htonl(IPAddress(sender->addr))),
									  false);
			  }
			}
			pregrouplen += sizeof(*grouprecord);
		  }

		// (XXX) This join is also generated on a router directly connected to the sender.
		
		break;
	  default:
		debug_msg("PIM does not know this type of message!");
	  }

	  	output(1).push(p);  
  }
  else {
	//	debug_msg("no PIM message");
	output(0).push(p);  
  }  
}

EXPORT_ELEMENT(PIM)
