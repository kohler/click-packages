/*
 * IP6PIMForwardingTable.{cc,hh} -- data structure for multicast groups and receivers
 * Martin Hoffmann
 *
 * Copyright (c) 2005, 2006 University of Bristol, University of Hannover
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
#include "ip6pimforwardingtable.hh"
#include <click/ipaddress.hh>
#include <click/router.hh>
#include <click/error.hh>
#include <click/ip6address.hh>
#include <click/confparse.hh>
#include "debug.hh"


IP6PIMForwardingTable::IP6PIMForwardingTable()
{
}

IP6PIMForwardingTable::~IP6PIMForwardingTable()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: copies the list of PIM enabled incoming interfaces to the PIMForwardingTable *
 *            these pim enabled addresses can also be derived from the PIM hello-messages  * 
 *                                                                                         *
 *******************************************************************************************/
int
IP6PIMForwardingTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
  
  if (conf.size() < 1)
    return errh->error("too few arguments to `IP6PIMForwardingTable([ADDRS])'");
 
  Vector<String> ips; 

  if (conf.size()) {
    Vector<String> words;
    cp_spacevec(conf[0], words);
    click_in6_addr a;
    for (int j = 0; j < words.size(); j++) {
      if (!cp_ip6_address(words[j], (unsigned char *)&a)) { 
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
    debug_msg("IP6PIMForwardingTable ipaddress %x", (*i).interface.data());
	} */
  return 0; 
}


/*******************************************************************************************
 *                                                                                         *
 * addgroup: adds  group, source and upstream neighbor address to an existing interface    * 
 *                                                                                         *
 *******************************************************************************************/
bool IP6PIMForwardingTable::addgroup(IP6Address interface,
				     IP6Address group,
				     IP6Address source,
				     IP6Address upstreamneighbor)
{

  debug_msg("IP6PIMForwardingTable PIM addgroup");

  groupsource gs;
  gs.neighbor=upstreamneighbor;
  gs.group=group;
  gs.source=source;

  // go through all pim interfaces...
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	if( IP6Address((*i).interface) == IP6Address(interface) )
	  {
		// and check for double entries...
		Vector<groupsource>::iterator g;
		for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
		  if( (*g).group==IP6Address(gs.group) ) return false;
		}
		// before finally adding the group address.
		(*i).groupsources.push_back(gs);
		printgroups();
		return true;
	  }
  }
  return false;
}

bool IP6PIMForwardingTable::delgroup(IP6Address interface, IP6Address group, IP6Address source, IP6Address upstreamneighbor)
{

  debug_msg("IP6PIMForwardingTable PIM delgroup");

  // go through all pim interfaces...
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	if( IP6Address((*i).interface) == IP6Address(interface) )
	  {
		debug_msg("IP6PIMForwardingTable delgroup found interface");
		// and check for group entries...
		Vector<groupsource>::iterator g;
		for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
		  //debug_msg("IP6PIMForwardingTable delgroup at source %x", IP6Address(source));
		  //	debug_msg("IP6PIMForwardingTable delgroup at group %x", IP6Address(group));
			//		  if( ( (*g).group.addr()==IP6Address(group) ) &&  ( (*g).source.addr()==htonl(source.addr())) ) { (X)
	
		  if( //( (*g).source==IP6Address(source)) &&  // not for mldv1 and embedded rp addres
		     (*g).group==IP6Address(group)   ) {

			(*i).groupsources.erase(g);
			return true;
		  }
		}
	  }
  }
  return false;
}

bool IP6PIMForwardingTable::addinterface(IP6Address interface, IP6Address neighbor)
{
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) {
	if(IP6Address((*i).interface)==IP6Address(interface)) return false;
  }
  piminterface newinterface;
  newinterface.interface=IP6Address(interface);
  newinterface.neighbor=IP6Address(neighbor);
  piminterfaces.push_back(newinterface);
  return true;

}

bool IP6PIMForwardingTable::delgroup(IP6Address group)
{
  //  debug_msg("IP6PIMForwardingTable Delgroup %x", group);
  return true;
}

bool IP6PIMForwardingTable::printgroups()
{
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	  {
		Vector<groupsource>::iterator g;
		for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
		  //		  debug_msg("IP6PIMForwardingTable PIM: g-%x s-%x n-%x", (*g).group.addr(), (*g).source.addr(), (*g).neighbor.addr());
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
void IP6PIMForwardingTable::push(int port, Packet *p_in)
{
  IP6Address group=DST_IP6_ANNO(p_in);
  click_ip6* ip;
  ip=(click_ip6 *)p_in->data();
  IP6Address source=IP6Address(ip->ip6_src);
  if(piminterfaces.size()!=0) {
	Vector<piminterface>::iterator  i;
	for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i)
	  {

		if((*i).groupsources.size() != 0)
		  {
			Vector<groupsource>::iterator  g;
			for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {

			  if( // (*g).source==source && not for embedded RP and MLDv1...
			     group==(*g).group)
				{
				  Packet *q_in = p_in->clone();
				  WritablePacket *p = q_in->uniqueify();
				  SET_DST_IP6_ANNO(p, (*i).neighbor);
				  output(0).push(p);
				  // debug_msg("IP6PIMForwardingTable forwarding ...");
				}
			}
		  }
		else
		  {
			//	debug_msg("IP6PIMForwardingTable PIM forwarding table is empty, no other PIM routers requested this group");
		  }
		
	  }
  }
}


click_in6_addr IP6PIMForwardingTable::get_upstreamneighbor(IP6Address interface)
{
  if(piminterfaces.size()!=0) {
	Vector<piminterface>::iterator  i;
	for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i)
	  {
	    if((*i).interface==interface) 
	      {
		return click_in6_addr((*i).neighbor);
	      } 
	  }
  }
  return click_in6_addr(IP6Address("0::0"));
}

// returns false if no PIM receivers are known
bool IP6PIMForwardingTable::getPIMreceivers(IP6Address source, IP6Address group)
{
  Vector<piminterface>::iterator i;
  for(i=piminterfaces.begin(); i!=piminterfaces.end(); ++i) { 
	{
	  Vector<groupsource>::iterator g;
	  for(g=(*i).groupsources.begin(); g!=(*i).groupsources.end(); ++g) {
	    //		debug_msg("PIMForwardingTable getPIMreceivers: source %x group %x", source.addr(), group.addr());

		if((*g).source==source && group==(*g).group) {
		   debug_msg("PIMForwardingTable getPIMreceivers: found active group");
		  return true;
		}
	  }
	}
  }
  return false;
}


EXPORT_ELEMENT(IP6PIMForwardingTable)
