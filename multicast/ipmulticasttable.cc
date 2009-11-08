/*
 * ipmulticasttable.{cc,hh} -- data structure for multicast groups and receivers
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
#include "ipmulticasttable.hh"
#include "pimcontrol.hh"
#include <click/ipaddress.hh>
#include <click/router.hh>
#include <click/confparse.hh>
#include "debug.hh"

IPMulticastTable::IPMulticastTable()
{
}

IPMulticastTable::~IPMulticastTable()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get pointer to pim element                                                   *
 *                                                                                         *
 *******************************************************************************************/
int
IPMulticastTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 0) {
	cp_unsigned(conf[0], &no_of_interfaces);
	debug_msg("IPMulticasttable: IGMP interfaces %d", no_of_interfaces);
  }
  if (conf.size() == 1) {
    debug_msg("IPMulticasttable: No PIM-SM elements named, router-to-router protocol is disabled.");
	pimenable=false;
	return 0;
  }
  else {
	pimenable=true;
	//  get PIMControl element
	Element *e = cp_element(conf[1], this, errh);
	if (!e) {
	  return -1;
	}
	pPim = (PIMControl *)e->cast("PIMControl");
	return 0;
  }
}

int
IPMulticastTable::initialize(ErrorHandler *errh)
{
  bool b=false;

  for(unsigned int i=0; i<no_of_interfaces; ++i) { 
	interfaces.push_back(b);
  }
  return 0;
}

bool IPMulticastTable::addgroup(IPAddress group)
{
  MulticastGroup newgroup;
  newgroup.group = group;
  Vector<MulticastGroup>::iterator i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) { 
	if(IPAddress((*i).group)==IPAddress(group)) return false;
  }
  multicastgroups.push_back(newgroup);
  const unsigned char *p = group.data();
  debug_msg("IPMulticasttable: Added IP group address: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);

  return true;

}

/*******************************************************************************************
 *                                                                                         *
 * joingroup: adds a receiver to a group                                                   *
 *                                                                                         *
 *******************************************************************************************/
bool IPMulticastTable::joingroup(IPAddress recv, IPAddress group, unsigned int interface)
{
  receiver new_receiver;           // create new receiver struct
  new_receiver.receiver=recv;      // initialize this new struct with receivers IP address

  Vector<MulticastGroup>::iterator i;

   for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {

	if((*i).group.addr()==group.addr()) {

	  // search for duplicate entries
	  
	  Vector<receiver>::iterator a;
	  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a) {
		if( (*a).receiver.addr()==recv.addr() ) { 
		  const unsigned char *p = group.data();
		  const unsigned char *p2 = recv.data();
		  debug_msg("IPMulticasttable: Duplicate request to add %d.%d.%d.%d to group %d.%d.%d.%d - ignored", p2[0], p2[1], p2[2], p2[3], p[0], p[1], p[2], p[3]);
		  return false;  
		}
	  }
	  const unsigned char *p = group.data();
	  const unsigned char *p2 = recv.data();
	  	  debug_msg("IPMulticasttable: Adding %d.%d.%d.%d to group %d.%d.%d.%d", p2[0], p2[1], p2[2], p2[3], p[0], p[1], p[2], p[3]);
		  (*i).interface_id=interface;
		  (*i).receivers.push_back(new_receiver); 
	}
  }
   // printgroups(true);
  return true;
  //  multicastgroups[0].receivers.push_back(recv);
}

/*******************************************************************************************
 *                                                                                         *
 * leavegroup: delets a receiver from a group                                              *
 *             and deletes the group if it is empty                                        *
 *                                                                                         *
 *******************************************************************************************/
bool IPMulticastTable::leavegroup(IPAddress recv, IPAddress group)
{
  Vector<MulticastGroup>::iterator i;

  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {


	if((*i).group.addr()==group.addr()) {
	  debug_msg("IPMulticasttable: leavegroup found group");

	  // search for duplicate entries
	  
	  Vector<receiver>::iterator a;
	  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a) {
		if( (*a).receiver.addr()==recv.addr() ) {
		  const unsigned char *p = group.data();
		  const unsigned char *p2 = recv.data();
		  debug_msg("IPMulticasttable: Delete %d.%d.%d.%d from group %d.%d.%d.%d", 
					p2[0], p2[1], p2[2], p2[3], 
					p[0], p[1], p[2], p[3]);
		  (*i).receivers.erase(a);
		  printgroups(true);


		  // if no more receivers exist, the group is deleted
		  if((*i).receivers.begin()==(*i).receivers.end()) {
			// (XXX) send a listener query first
			multicastgroups.erase(i);
			debug_msg("IPMulticasttable: deleted group");
			return true;
		  }
		  return true;  
		}
	  }
	  const unsigned char *p = group.data();
	  const unsigned char *p2 = recv.data();
	  debug_msg("IPMulticasttable: %d.%d.%d.%d not found in group %d.%d.%d.%d - not deleted",
				p2[0], p2[1], p2[2], p2[3],
				p[0], p[1], p[2], p[3]);

	}
  }

  return false; 
}

/*******************************************************************************************
 *                                                                                         *
 * printreceiver: called by printgroups                                                    *
 *                displays receivers in a group and their sources (if existing)            *
 *                                                                                         *
 *******************************************************************************************/
bool IPMulticastTable::printreceiver(Vector<MulticastGroup>::iterator i)
{
  Vector<receiver>::iterator re;
  for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re) {
	const unsigned char *p = (*re).receiver.data();
	Vector<IPAddress>::iterator a;
	debug_msg("IPMulticasttable: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	short si;
	si=0;
	for(a=(*re).sources.begin(); a!=(*re).sources.end(); ++a) {
	  const unsigned char *p = (*a).data();
	  si++;
	  debug_msg("IPMulticasttable: source %d %d.%d.%d.%d mode %x", 
				si,
				p[0], p[1], p[2], p[3],
				(*re).mode);
	}
  }
  return true; 
}

/*******************************************************************************************
 *                                                                                         *
 * printgroup: prints all known multicast groups                                           *
 *             if printreceivers is true, all receivers and sources are printed as well    *
 *                                                                                         *
 *******************************************************************************************/
bool IPMulticastTable::printgroups(bool printreceivers)
{
  Vector<MulticastGroup>::iterator i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {
	const unsigned char *p = (*i).group.data();
	debug_msg("IPMulticasttable: IP group address: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	if(printreceivers) {
	  	debug_msg("IPMulticasttable: receivers in group:");
		printreceiver(i);
	}
  }
  return true;
}

/*******************************************************************************************
 *                                                                                         *
 * push: every arriving packet is handled by the oush function                             *
 *             the forwarding of a multicast packet is done here                           *
 *                                                                                         *
 *******************************************************************************************/
void IPMulticastTable::push(int port, Packet *p_in)
{
  bool submitted_packet=false;
  IPAddress group=IPAddress(p_in->dst_ip_anno());
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  //	  click_chatter("IPMulticasttable: scanning %x for %x",(*i).group.addr() ,group.addr());
	  if(((*i).receivers.size() != 0) && 
		 //		 interfaces[(*i).interface_id]==false &&
		 group.addr()==(*i).group.addr())

		
		{
		  //	  click_chatter("IPMulticasttable: ipv4mct push found group");
		  interfaces[(*i).interface_id]=true;
		  Vector<receiver>::iterator a;
		  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a)
			{
			  submitted_packet=true;
			  Packet *q_in = p_in->clone();
			  WritablePacket *p = q_in->uniqueify();
			  click_ip *ip = p->ip_header();
			  ip->ip_ttl=(ip->ip_ttl)-1;
			  IPAddress r=IPAddress((*a).receiver.addr());
			  q_in->set_dst_ip_anno(r);
			  int hlen = ip->ip_hl << 2;
			  ip->ip_sum = 0;
			  ip->ip_sum = click_in_cksum((unsigned char *)ip, hlen);
			  // debug_msg("IPMulticasttable: pushing packet with new dst_ip_anno to ip router");
			  output(0).push(p);
			}
		}
	}
  // after forwarding the multicast stream to all connected hosts, forward the stream to the PIM table
  // debug_msg("IPMulticasttable: IPMulticastTable pushes stream to PIM table");

  for(unsigned int intr=0; intr<(no_of_interfaces-1); ++intr) { 
	interfaces[intr]=false;
  }
  
  output(1).push(p_in);
}

/*******************************************************************************************
 *                                                                                         *
 * addsource: SSM function, adds a source address to a pair of group<->interface           *
 *                                                                                         *
 *******************************************************************************************/
bool IPMulticastTable::addsource(IPAddress recv, IPAddress group, IPAddress sa)
{
  debug_msg("IPMulticasttable: addsource");
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(group.addr()==(*i).group.addr()) 
		{
		  Vector<receiver>::iterator re;
		  for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re)
			{
			  if((*re).receiver.addr()==recv.addr()) {
				Vector<IPAddress>::iterator a;
				for(a=(*re).sources.begin(); a!=(*re).sources.end(); a++) {
				  if((*a).addr()==ntohl(sa.addr())) {
					debug_msg("IPMulticasttable: addsource: Duplicate request to add source");
					return false;
				  }

				}
				(*re).sources.push_back(ntohl(IPAddress(sa)));
				if (pimenable==true) {
				  debug_msg("IPMulticasttable: PIM join");
				  pPim->join(group, sa);
				}
				const unsigned char *p = sa.data();
				debug_msg("IPMulticasttable: IPMulticastTable IP source address: %d.%d.%d.%d", p[3], p[2], p[1], p[0]);
				return true;				
			  }
			}
		}
	}
  return false;
}

/*******************************************************************************************
 *                                                                                         *
 * addsource: SSM function, adds a source address to a pair of group<->interface           *
 *                                                                                         *
 *******************************************************************************************/
bool IPMulticastTable::delsource(IPAddress recv, IPAddress group, IPAddress sa)
{
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(group.addr()==(*i).group.addr()) 
		{
		  Vector<receiver>::iterator re;
		  for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re)
			{
			  if((*re).receiver.addr()==recv.addr()) {
				Vector<IPAddress>::iterator a;
				for(a=(*re).sources.begin(); a!=(*re).sources.end(); ++a) {
				  if((*a).addr()==sa.addr()) {
					(*re).sources.erase(a);
					// "dead" receivers are dropped from the list
					if((get_receiver_mode(recv, group)==INCLUDEMODE) && ((*re).sources.size()==0)) {
					  leavegroup(recv, group);
					  // if this group has no more receivers connected to the router PIM is informed
					  if ((pimenable) && (pPim->noPIMreceivers(group, htonl(sa)))) pPim->prune(group, htonl(sa));
					  return true;
					}
				  }
				}
			  }
			}
		}
	}
  return false;
}

unsigned char
IPMulticastTable::get_receiver_mode(IPAddress recv, IPAddress group)
{
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(group.addr()==(*i).group.addr()) 
		{
		  Vector<receiver>::iterator a;
		  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a)
			{
			  if((*a).receiver.addr()==recv.addr())  return (*a).mode;
			}
		}
	}
  return MODE_NOT_SET;
}


bool
IPMulticastTable::set_receiver_mode(IPAddress recv, IPAddress group, MODE mode)
{
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(group.addr()==(*i).group.addr()) 
		{
		  debug_msg("IPMulticasttable: found group");
		  Vector<receiver>::iterator a;
		  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a)
			{
			  if((*a).receiver.addr()==recv.addr())  {
				(*a).mode=mode;
				return true;
				debug_msg("IPMulticasttable: setmode %x", mode);
			  }
			}
		}
	}
  return false;
}

// check whether IGMP listeners are attached or not
bool IPMulticastTable::getIGMPreceivers(IPAddress source, IPAddress group)
{
  debug_msg("IPMulticasttable: ********************");
  printgroups(true);
  debug_msg("IPMulticasttable: ********************");

  Vector<MulticastGroup>::iterator i;

  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {
    if((*i).group.addr()==group.addr()) {
      debug_msg("IPMulticasttable: getIGMPreceivers found group");
      Vector<receiver>::iterator re;
      for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re) {
	debug_msg("IPMulticasttable: searching for recvs in group %x", (*i).group.addr() );
	Vector<IPAddress>::iterator a;
	debug_msg("IPMulticasttable: groessse sources %d", (*re).sources.size() );
	for(a=(*re).sources.begin(); a!=(*re).sources.end(); ++a) {
	  debug_msg("IPMulticasttable: search %x from group %x", source.addr(), group.addr() );
	  debug_msg("IPMulticasttable: compare %x to %x", source.addr(), (*a).addr() );
	  if( (*a).addr()==(source.addr()) ) return false; 
	}
      }
    }
  }
  return true; 
}

EXPORT_ELEMENT(IPMulticastTable)
  
