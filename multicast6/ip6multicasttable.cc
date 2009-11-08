/*
 * IP6MulticastTable.{cc,hh} -- IPv6 data structure for multicast groups and receivers 
 * Martin Hoffmann
 *
 * Copyright (c) 2005,2006 University of Bristol, University of Hannover
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
#include <click/error.hh>
#include <click/confparse.hh>
#include "ip6multicasttable.hh"

IP6MulticastTable::IP6MulticastTable()
{
}

IP6MulticastTable::~IP6MulticastTable()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get pointer to pim element                                                   *
 *                                                                                         *
 *******************************************************************************************/
int
IP6MulticastTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1) {
	use_pim = false;
    debug_msg("No PIM-SM element named, router-to-router protocol is disabled.");
	return 0;
  }
  else {
  //  if (conf.size() == 1) {
	//  get PIM_Forwarding element
	Element *e = cp_element(conf[0], this, errh);
	if (!e) {
	  return -1;
	}
	pPim = (IP6PIMControl *)e->cast("IP6PIMControl");
	/*  }
		else {
 // return errh->error("wrong number of arguments; expected 'IP6MulticastTable(optional PIM element)'");
	}  */
	return 0;
  }
}


void
IP6MulticastTable::printIP6(IP6Address group)
{
  debug_msg("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", (unsigned char)(* group.data() + 0),(unsigned char)(* (group.data() + 1)), (unsigned char)(* (group.data() + 2)), (unsigned char)(* (group.data() + 3)),(unsigned char)(* (group.data() + 4)), (unsigned char)(* (group.data() + 5)), (unsigned char)(* (group.data() + 6)), (unsigned char)(* (group.data() + 7)), (unsigned char)(* (group.data() + 8)), (unsigned char)(* (group.data() + 9)), (unsigned char)(* (group.data() + 10)), (unsigned char)(* (group.data() + 11)), (unsigned char)(* (group.data() + 12)), (unsigned char)(* (group.data() + 13)), (unsigned char)(* (group.data() + 14)), (unsigned char)(* (group.data() + 15))  ); 
}


bool IP6MulticastTable::addgroup(IP6Address group)
{
  MulticastGroup newgroup;
  newgroup.group = group;
  Vector<MulticastGroup>::iterator i;
  // check if entry already exists
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) { 
	if(IP6Address((*i).group)==IP6Address(group)) return false;
  }
  multicastgroups.push_back(newgroup);
  //  pPim->join(group);
  return true;
}

/*******************************************************************************************
 *                                                                                         *
 * joingroup: adds a receiver to a group                                                   *
 *                                                                                         *
 *******************************************************************************************/
bool IP6MulticastTable::joingroup(IP6Address recv, IP6Address group)
{
  receiver new_receiver;           // create new receiver struct
  new_receiver.receiver=recv;      // initialize this new struct with receivers IP address

  Vector<MulticastGroup>::iterator i;

   for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {

	if(IP6Address((*i).group)==IP6Address(group)) {

	  // search for duplicate entries
	  
	  Vector<receiver>::iterator a;
	  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a) {
		if( IP6Address((*a).receiver)==IP6Address(recv) ) { 
		  //		  debug_msg("Duplicate request to add");
		  //		  printIP6(recv);
		  //		  debug_msg("to group");
		  //		  printIP6(group);
		  return false;  
		}
	  }
	  const unsigned char *p = group.data();
	  const unsigned char *p2 = recv.data();
	  debug_msg("Adding");
	  printIP6(recv);
	  debug_msg("  to group");
   	  printIP6(group);
	  (*i).receivers.push_back(new_receiver); 
	}
  }
   // printgroups(true);
  return true;
}

/*******************************************************************************************
 *                                                                                         *
 * leavegroup: delets a receiver from a group                                              *
 *             and deletes the group if it is empty                                        *
 *                                                                                         *
 *******************************************************************************************/
bool IP6MulticastTable::leavegroup(IP6Address recv, IP6Address group)
{

  Vector<MulticastGroup>::iterator i;

  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {


	if(IP6Address((*i).group)==IP6Address(group)) {
	  // debug_msg("leavegroup found group");

	  Vector<receiver>::iterator a;

	  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a) {
		if( IP6Address((*a).receiver)==IP6Address(recv) ) {
		  debug_msg("Deleting");
		  printIP6(recv);
		  debug_msg("  from group");
		  printIP6(group);
		  (*i).receivers.erase(a);
		  
		  // if no more receivers exist, the group is deleted
		  if((*i).receivers.begin()==(*i).receivers.end()) {
			// (XXX) send a listener query first
			multicastgroups.erase(i);
			return true;
		  }
		  return true;
		}
	  }
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
bool IP6MulticastTable::printreceiver(Vector<MulticastGroup>::iterator i)
{
  Vector<receiver>::iterator re;
  for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re) {

	Vector<click_in6_addr>::iterator a;
	debug_msg("  receiver:");
	printIP6(IP6Address((*re).receiver));
	for(a=(*re).sources.begin(); a!=(*re).sources.end(); ++a) {
	  debug_msg("    allowed source");
	  printIP6(IP6Address((*a)));
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
bool IP6MulticastTable::printgroups(bool printreceivers)
{
  Vector<MulticastGroup>::iterator i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {
	debug_msg("Printing groups: IP group address:");
	printIP6(IP6Address((*i).group));
	if(printreceivers) {
	  	debug_msg("receivers in group:");
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
void IP6MulticastTable::push(int port, Packet *p_in)
{
  bool submitted_packet=false;
  click_in6_addr group=click_in6_addr(DST_IP6_ANNO(p_in));
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(((*i).receivers.size() != 0) && IP6Address(group)==IP6Address((*i).group)) 

		{
		  Vector<receiver>::iterator a;
		  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a)
			{
			  submitted_packet=true;
			  Packet *q_in = p_in->clone();
			  WritablePacket *p = q_in->uniqueify();
			  click_ip6 *ip = p->ip6_header();
			  ip->ip6_hlim++;
			  click_in6_addr r=click_in6_addr((*a).receiver);
			  SET_DST_IP6_ANNO(p, r);
			  output(0).push(p);
			}
		}
	}
	output(1).push(p_in);
}

/*******************************************************************************************
 *                                                                                         *
 * addsource: SSM function, adds a source address to a pair of group<->interface           *
 *                                                                                         *
 *******************************************************************************************/
bool IP6MulticastTable::addsource(IP6Address recv, IP6Address group, IP6Address sa)
{
  //  debug_msg("addsource");
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(IP6Address(group)==IP6Address((*i).group)) 
		{
		  Vector<receiver>::iterator re;
		  for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re)
			{
			  if(IP6Address((*re).receiver)==IP6Address(recv)) {
				Vector<click_in6_addr>::iterator a;
				for(a=(*re).sources.begin(); a!=(*re).sources.end(); a++) {
				  //  if(IP6Address((*a))==IP6Address(sa)) {// PIM-Embedded RP test
					//					debug_msg("addsource: Duplicate request to add source");
				  return false; 
				  //				  }

				}
				(*re).sources.push_back(click_in6_addr(sa));
				//const unsigned char *p = sa.data();
				//	debug_msg("IP source address: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);
				if ( (pPim->noPIMreceivers(group, sa)) ) {
					  pPim->generatejoinprune(group, sa, true);
				  	}
				return true;				
			  }
			}
		}
	}
  return false;
}

/*******************************************************************************************
 *                                                                                         *
 * delsource: SSM function, deletes a source address from a pair of group<->interface      *
 *                                                                                         *
 *******************************************************************************************/
bool IP6MulticastTable::delsource(IP6Address recv, IP6Address group, IP6Address sa)
{
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(IP6Address(group)==IP6Address((*i).group)) 
		{
		  Vector<receiver>::iterator re;
		  for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re)
			{
			  if(IP6Address((*re).receiver)==IP6Address(recv)) {
				Vector<click_in6_addr>::iterator a;
				for(a=(*re).sources.begin(); a!=(*re).sources.end(); ++a) {
				  if(IP6Address((*a))==IP6Address(sa)) {
					(*re).sources.erase(a);
					// "dead" receivers are dropped from the list
					if((get_receiver_mode(recv, group)==INCLUDEMODE) && ((*re).sources.size()==0)) leavegroup(recv, group); 
					if ( pPim->noPIMreceivers(group, sa) ) {
					  pPim->generatejoinprune(group, sa, false);
					}
					return true;
				  }
				}
			  }
			}
		}
	}
  return false;
}

unsigned char
IP6MulticastTable::get_receiver_mode(IP6Address recv, IP6Address group)
{
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(IP6Address(group)==IP6Address((*i).group)) 
		{
		  Vector<receiver>::iterator a;
		  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a)
			{
			  if(IP6Address((*a).receiver)==IP6Address(recv))  return (*a).mode;
			}
		}
	}
  return MODE_NOT_SET;
}


bool
IP6MulticastTable::set_receiver_mode(IP6Address recv, IP6Address group, MODE mode)
{
  Vector<MulticastGroup>::iterator  i;
  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i)
	{
	  if(IP6Address(group)==IP6Address((*i).group)) 
		{
		  //		  debug_msg("found group");
		  Vector<receiver>::iterator a;
		  for(a=(*i).receivers.begin(); a!=(*i).receivers.end(); ++a)
			{
			  if(IP6Address((*a).receiver)==IP6Address(recv))  {
				(*a).mode=mode;
				return true;
				//				debug_msg("setmode %x", mode);
			  }
			}
		}
	}
  return false;
}

// check whether MLD listeners are attached or not
bool IP6MulticastTable::getMLDreceivers(IP6Address source, IP6Address group)
{
  Vector<MulticastGroup>::iterator i;

  for(i=multicastgroups.begin(); i!=multicastgroups.end(); ++i) {
    if(IP6Address((*i).group)==IP6Address(group)) {
      debug_msg("IP6Multicasttable: getMLDreceivers found group");
      Vector<receiver>::iterator re;
      for(re=(*i).receivers.begin(); re!=(*i).receivers.end(); ++re) {
	Vector<click_in6_addr>::iterator a;
	for(a=(*re).sources.begin(); a!=(*re).sources.end(); ++a) {
	  //	  if( IP6Address(*a)==IP6Address(source) ) // non SSM test
	    return false; 
	}
      }
    }
  }
  return true; 
}

EXPORT_ELEMENT(IP6MulticastTable)
