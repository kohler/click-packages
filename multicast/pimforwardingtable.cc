/*
 * PIMForwardingTable.{cc,hh} -- data structure for multicast groups and receivers
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
#include "pimforwardingtable.hh"
#include <click/ipaddress.hh>
#include <click/router.hh>
#include <click/error.hh>
#include <click/confparse.hh>
#include "debug.hh"

PIMForwardingTable::PIMForwardingTable()
{
}

PIMForwardingTable::~PIMForwardingTable()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: copies the list of PIM enabled incoming interfaces to the PIMForwardingTable *
 *            these pim enabled addresses can also be derived from the PIM hello-messages  * 
 *                                                                                         *
 *******************************************************************************************/
int
PIMForwardingTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
  
  if (conf.size() < 1)
    return errh->error("too few arguments to `PIMForwardingTable([ADDRS])'");
 
  Vector<String> ips; 

  if (conf.size()) {
    Vector<String> words;
    cp_spacevec(conf[0], words);
    IPAddress a;
    for (int j = 0; j < words.size(); j++) {
      if (!cp_ip_address(words[j], &a)) { 
		return errh->error("expects IPADDRESS -a ");
      }
	  else {
		piminterface pt;
		pt.interface=a;
		//		piminterfaces.push_back(pt);
	  }
	}
  }
  /*  Vector<pimtable>::iterator i;
  for(i=pim_interfaces.begin(); i!=pim_interfaces.end(); i++){
    debug_msg("PIMForwardingTable: ipaddress %x", (*i).interface.data());
	} */
  return 0; 
}


/*******************************************************************************************
 *                                                                                         *
 * addgroup: adds  group, source and upstream neighbor address to an existing interface    * 
 *                                                                                         *
 *******************************************************************************************/
bool PIMForwardingTable::addgroup(IPAddress interface,
								  IPAddress group,
								  IPAddress source,
								  IPAddress upstreamneighbor)
{

  debug_msg("PIMForwardingTable: PIM addgroup");

  groupsource gs;
  //  gs.neighbor=IPAddress(ntohl(upstreamneighbor));
  gs.group=IPAddress((group));
  gs.source=IPAddress(ntohl(source));

  // go through all pim interfaces...
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	if( IPAddress((*i).interface) == IPAddress(interface) )
	  {
		// and check for double entries...
		Vector<groupsource>::iterator g;
		for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
		  if( (*g).group.addr()==gs.group.addr() ) return false;
		}
		// before finally adding the group address.
		(*i).groupsources.push_back(gs);
		printgroups();
		return true;
	  }
  }
  return false;
}

bool PIMForwardingTable::delgroup(IPAddress interface,
								  IPAddress group,
								  IPAddress source,
								  IPAddress upstreamneighbor)
{

  debug_msg("PIMForwardingTable: PIM delgroup");

  // go through all pim interfaces...
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	if( IPAddress((*i).interface) == IPAddress(interface) )
	  {
		debug_msg("PIMForwardingTable: delgroup found interface");
		// and check for group entries...
		Vector<groupsource>::iterator g;
		for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
			debug_msg("PIMForwardingTable: delgroup at source %x", source.addr());
			debug_msg("PIMForwardingTable: delgroup at group %x", group.addr());
		  if( ( (*g).group.addr()==group.addr() ) &&  ( (*g).source.addr()==htonl(source.addr())) ) {

			(*i).groupsources.erase(g);
			return true;
		  }
		}
	  }
  }
  return false;
}

bool PIMForwardingTable::addinterface(IPAddress interface, IPAddress neighbor)
{
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) {
	if(IPAddress((*i).interface)==IPAddress(interface)) return false;
  }
  debug_msg("PIMForwardingTable: PIM addinterface");
  piminterface newinterface;
  newinterface.interface=IPAddress(interface);
  newinterface.neighbor=IPAddress(neighbor);
  piminterfaces.push_back(newinterface);
  return true;

}

bool PIMForwardingTable::printgroups()
{
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	  {
		Vector<groupsource>::iterator g;
		for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
		  debug_msg("PIMForwardingTable: PIM: g-%x s-%x n-%x", (*g).group.addr(), (*g).source.addr(), (*g).neighbor.addr());
		}
	  }
  }
  return true;
}

/*******************************************************************************************
 *                                                                                         *
 * push: each arriving packet is handled by the push function                              *
 *             the forwarding of a multicast packet is done here                           *
 *             incoming multicast traffic with no destination to go to is silently ignored *
 *                                                                                         *
 *******************************************************************************************/
void PIMForwardingTable::push(int port, Packet *p_in)
{
  IPAddress group=IPAddress(p_in->dst_ip_anno());
  click_ip* ip;
  ip=(click_ip *)p_in->data();
  IPAddress source=IPAddress(ip->ip_src);
  if(piminterfaces.size()!=0) {
	Vector<piminterface>::iterator  i;
	for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i)
	  {

		if((*i).groupsources.size() != 0)
		  {
			Vector<groupsource>::iterator  g;
			for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
			  //			  click_chatter("PIMForwardingTable: comparing %x to %x",(*g).group.addr(), group.addr()); 
			  if((*g).source.addr()==ntohl(source.addr()) && (group.addr())==((*g).group.addr())) 
				{
				  Packet *q_in = p_in->clone();
				  WritablePacket *p = q_in->uniqueify();
				  click_ip *ip = p->ip_header();
				  ip->ip_ttl=(ip->ip_ttl)-1;
				  //				  p->set_dst_ip_anno(IPAddress(htonl((*g).neighbor.addr())));
				  p->set_dst_ip_anno(IPAddress((*i).neighbor.addr()));
				  int hlen = ip->ip_hl << 2;
				  ip->ip_sum = 0;
				  ip->ip_sum = click_in_cksum((unsigned char *)ip, hlen);
				  output(0).push(p);
				  // click_chatter("PIMForwardingTable: forwarding ...");
				}
			}
		  }
		else
		  {
			//	debug_msg("PIMForwardingTable: PIM forwarding table is empty, no other PIM routers requested this group");
		  }
		
	  }
  }
}

uint32_t PIMForwardingTable::get_upstreamneighbor(IPAddress interface)
{
  if(piminterfaces.size()!=0) {
	Vector<piminterface>::iterator  i;
	for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i)
	  {
		  if((*i).interface.addr()==interface.addr()) 
			{
			  //	  click_chatter("interafce %x -- neighbor %x",(*i).interface,(*i).neighbor );
			  return IPAddress((*i).neighbor);
			} 
		}
  }
  return 0;
}

// returns false if no PIM receivers are known
bool PIMForwardingTable::getPIMreceivers(IPAddress source, IPAddress group)
{
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	{
	  Vector<groupsource>::iterator g;
	  for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
		debug_msg("PIMForwardingTable getPIMreceivers: source %x group %x", source.addr(), group.addr());
		if((*g).source.addr()==(source.addr()) && (group.addr())==((*g).group.addr())) {
		  debug_msg("PIMForwardingTable getPIMreceivers: found active group");
		  return false;
		}
	  }
	}
  }
  return true;
}

EXPORT_ELEMENT(PIMForwardingTable)
