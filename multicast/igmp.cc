/*
 * IGMP.{cc,hh} -- IGMPv3 processing element
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
#include "protocoldefinitions.hh"
#include "igmp.hh"
#include "ipmulticasttable.hh"
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>
#include "debug.hh"

IGMP::IGMP(): _igmptimer(this)
{
}

IGMP::~IGMP()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get name of MulticastTable element to access datastructures                  *
 *                                                                                         *
 *******************************************************************************************/
int
IGMP::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("wrong number of arguments; expected 'IGMP(MulticastTable element)'");

  // get MulticastTable element
  Element *e = cp_element(conf[0], this, errh);
  if (!e) {
    return -1;
  }
  else {
	MCastTable = (IPMulticastTable *)e->cast("IPMulticastTable");
	return 0;
  }
}

/*******************************************************************************************
 *                                                                                         *
 * initialization: initialize timer                                                        *
 *                                                                                         *
 *******************************************************************************************/
int IGMP::initialize(ErrorHandler *errh)
{
  _igmptimer.initialize(this);
  _igmptimer.schedule_after_msec(INTERVAL);

  /*****************************************************************************************
  // ** for performance tests, add a number of groups and receivers ***
  IPAddress group;
  //IP6Address recv=(IP6Address(0));
  IPAddress src;
  //  recv=IPAddress("192.168.30.2");

    for(unsigned int i=1; i < 50001; i++)
	{
	  MCastTable->addgroup(IPAddress(i));
	  //	  MCastTable->joingroup(IPAddress(i), IPAddress(~i));  
	}

  group=IPAddress("232.2.2.2");
  MCastTable->addgroup(group);


  for(unsigned int i; i < 10; i++)
	{
	  	  MCastTable->joingroup(IPAddress(i), group, 1);  

	}


  group=IPAddress("232.2.2.3");
  MCastTable->addgroup(group);


  for(unsigned int i=1; i < 10; i++)
	{
	  	  MCastTable->joingroup(IPAddress(i), group, 1);  
	}

  group=IPAddress("232.2.2.1");
  MCastTable->addgroup(group);


  for(unsigned int i; i < 10; i++)
	{
	  	  MCastTable->joingroup(IPAddress(i), group,1);  

	} 
	****************************************** end of performance test *********************/
  return 0;
}

/*******************************************************************************************
 *                                                                                         *
 * simpleaction: each arriving packet is examined here                                    *
 *                                                                                         *
 *******************************************************************************************/
Packet *
IGMP::simple_action(Packet *p)
{
  const click_ip *ip = p->ip_header();
  void *igmpmessage = (void *) (p->data() + (ip->ip_hl * 4));
  
  /* this variable saves the IGMP message ID
   * the following IDs are reckognized 
   * RFC 1112 IGMPv1: 11= query 12= join group
   * RFC 2236 IGMPv2: 11= query 16= join group 17= leave group
   * RFC 3376 IGMPv3: 11= query 22= join or leave group 
   */

  unsigned short grouprecord_counter;

  switch(*(char *)igmpmessage)
	{
	case 0x11:
	  // (XXX) this has to be filled with some action, start election of active querier
	  debug_msg("IGMP query from %x", ip->ip_src);
	  break;
	  
	case 0x12:
	  if(click_in_cksum((unsigned char*)igmpmessage, sizeof(igmpv1andv2message))!=0) {
		debug_msg("IGMPv1 report has wrong checksum!");
	  }
	  MCastTable->addgroup(ip->ip_dst);
	  MCastTable->joingroup(IPAddress(ip->ip_src), IPAddress(ip->ip_dst), PAINT_ANNO(p));
	  break;
	  
	case 0x16:
	  if(click_in_cksum((unsigned char*)igmpmessage, sizeof(igmpv1andv2message))!=0) {
		debug_msg("IGMPv2 join message has wrong checksum!");
	  }
	  MCastTable->addgroup(ip->ip_dst);
	  MCastTable->joingroup(IPAddress(ip->ip_src), IPAddress(ip->ip_dst), PAINT_ANNO(p));
	  break;
	  
	case 0x17:
	  if(click_in_cksum((unsigned char*)igmpmessage, sizeof(igmpv1andv2message))!=0) {
		debug_msg("IGMPv2 leave message has wrong checksum!");
	  }
	  v1andv2message = (igmpv1andv2message *) igmpmessage;
	  MCastTable->leavegroup(IPAddress(ip->ip_src), IPAddress(v1andv2message->group) );
	  break;
	
	case 0x22:

	  if(click_in_cksum((unsigned char*)igmpmessage, (ntohs(ip->ip_len) - (ip->ip_hl * 4)))!=0) {
		debug_msg("IGMPv3 message has wrong checksum!");
	  }
	  v3report = (igmpv3report *) igmpmessage;

	  for(grouprecord_counter=0; grouprecord_counter < ntohs(v3report->no_of_grouprecords); grouprecord_counter++)
		{

		  switch(v3report->grouprecords[grouprecord_counter].type) {

		  case 0x01: 
			// host answered to a query, keepalive timer can be restarted, to be implemented in host
			debug_msg("MODE_IS_INCLUDE"); //recv group mode
			MCastTable->set_receiver_mode(IPAddress(ip->ip_src), IPAddress(v3report->grouprecords[grouprecord_counter].multicast_address), INCLUDEMODE);
			break; 

		  case 0x02:
			// host answered to a query, keepalive timer can be restarted, to be implemented in host
			debug_msg("MODE_IS_EXCLUDE"); 
			MCastTable->set_receiver_mode(IPAddress(ip->ip_src),
										  IPAddress(v3report->grouprecords[grouprecord_counter].multicast_address),
										  EXCLUDEMODE);
			break;

		  case 0x03:
			debug_msg("CHANGE_TO_INCLUDE_MODE");
			change_to_include_mode(IPAddress(ip->ip_src),
								   IPAddress(v3report->grouprecords[grouprecord_counter].multicast_address),
								   ntohs(v3report->grouprecords[grouprecord_counter].no_of_sources),
								   grouprecord_counter,
								   PAINT_ANNO(p));

			break;
		  case 0x04:
			debug_msg("CHANGE_TO_EXCLUDE_MODE");

			change_to_exclude_mode(IPAddress(ip->ip_src),
								   IPAddress(v3report->grouprecords[grouprecord_counter].multicast_address),
								   ntohs(v3report->grouprecords[grouprecord_counter].no_of_sources),
								   grouprecord_counter,
								   PAINT_ANNO(p));

			break;
		  case 0x05:
			debug_msg("ALLOW_NEW_SOURCES");
			allow_new_sources(IPAddress(ip->ip_src),
							  IPAddress(v3report->grouprecords[grouprecord_counter].multicast_address),
							  ntohs(v3report->grouprecords[grouprecord_counter].no_of_sources),
							  grouprecord_counter,
							  PAINT_ANNO(p));
			break;
		  case 0x06:
			debug_msg("BLOCK_OLD_SOURCES");
			block_old_sources(IPAddress(ip->ip_src),
							  IPAddress(v3report->grouprecords[grouprecord_counter].multicast_address),
							  ntohs(v3report->grouprecords[grouprecord_counter].no_of_sources),
							  grouprecord_counter );
			break;
		  default:
			break;
			debug_msg("Unknown type in IGMP grouprecord or bad group record pointer");
		  }
		}
	  break;
	  
	default:
	  debug_msg("unknown IGMP message");
	}
  return p;
}

/*******************************************************************************************
 *                                                                                         *
 * change_to_exclude_mode is called after the arrival of type 4 group records              *
 *                                                                                         *
 * it changes an interface mode to exclude, i.e. all given sources are not allowed         *
 *                                                                                         *
 *******************************************************************************************/
bool 
IGMP::change_to_exclude_mode(IPAddress recv,
							 IPAddress group,
							 unsigned short no_of_sources,
							 unsigned short groupcounter,
							 unsigned int paintanno) 
{
  MCastTable->addgroup(group);  
  MCastTable->joingroup(recv, group, paintanno);  
  MCastTable->set_receiver_mode(recv, group, EXCLUDEMODE);
  for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->addsource(recv,
							group,
							IPAddress(ntohl(v3report->grouprecords[groupcounter].sources[source_counter])));
	  query(group,
			IPAddress(ntohl(v3report->grouprecords[groupcounter].sources[source_counter])));
	}
  if(no_of_sources==0)  query(group, IPAddress("0.0.0.0"));
  return true;
}


/*******************************************************************************************
 *                                                                                         *
 * change_to_exclude_mode is called after the arrival of type 3 group records              *
 *                                                                                         *
 * it changes an interface mode to include, i.e. all given sources are allowed             *
 *                                                                                         *
 *******************************************************************************************/
bool 
IGMP::change_to_include_mode(IPAddress recv,
							 IPAddress group,
							 unsigned short no_of_sources,
							 unsigned short groupcounter,
							 unsigned int paintanno) 
{
  MCastTable->addgroup(group);  
  MCastTable->joingroup(recv, group, paintanno);  
  MCastTable->set_receiver_mode(recv, group, INCLUDEMODE);
  if(no_of_sources == 0) MCastTable->leavegroup(recv, group);
  else
	{
	  for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
		{
		  MCastTable->addsource(recv,
								group,
								IPAddress(ntohl(v3report->grouprecords[groupcounter].sources[source_counter])));
		  query(group,
				IPAddress(ntohl(v3report->grouprecords[groupcounter].sources[source_counter])));
		}
	}
  if(no_of_sources==0) query(group, IPAddress("0.0.0.0"));
  return true;
}

/*******************************************************************************************
 *                                                                                         *
 * allownewsources is called after the arrival of type 5 group records                     *
 *                                                                                         *
 * it adds all allowed source addresses to the multicasttable                              *
 *                                                                                         *
 *******************************************************************************************/	  
bool 
IGMP::allow_new_sources(IPAddress recv, IPAddress group, unsigned short no_of_sources, unsigned short groupcounter, unsigned int paintanno) 
{
  MCastTable->addgroup(group);  
  // before doing anything else a group has to be joined
  // if the receiver is already a listener of this group this request will be ignored
  MCastTable->joingroup(recv, group, paintanno);
  // the following line does NOT follow RFC 3376
  // since Microsofts Windows XP implementation of IGMPv3 requires this and it does not affect the Linux kernel
  // standard compliant implementation of IGMPv3 it is used here
  MCastTable->set_receiver_mode(recv, group, INCLUDEMODE);
  // the list of allowed sources is added to the multicast forwarding table
  for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->addsource(recv, group, IPAddress(ntohl(v3report->grouprecords[groupcounter].sources[source_counter])));
	  query(group, IPAddress(ntohl(v3report->grouprecords[groupcounter].sources[source_counter])));
	}
  if(no_of_sources==0)  query(group, IPAddress("0.0.0.0"));
  return true;
}

/*******************************************************************************************
 *                                                                                         *
 * blockoldsources is called after the arrival of type 6 group records                     *
 *                                                                                         *
 * it deletes all unwanted source addresses from the multicasttable                        *
 *                                                                                         *
 *******************************************************************************************/
bool
IGMP::block_old_sources(IPAddress recv, IPAddress group, unsigned short no_of_sources, unsigned short groupcounter) 
{
   for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->delsource(recv,
							group,
							IPAddress(v3report->grouprecords[groupcounter].sources[source_counter]));
	  query(group,
			IPAddress(v3report->grouprecords[groupcounter].sources[source_counter]));
	}
   if(no_of_sources==0) query(group, IPAddress("0.0.0.0"));
   return true;
}



/*******************************************************************************************
 *                                                                                         *
 * query is called to generate query messages. all arriving changes of state of an         *
 * interface are followed by a group/source specific query                                 *
 *                                                                                         *
 *                                                                                         *
 *******************************************************************************************/
void
IGMP::query(IPAddress group, IPAddress source)
{
  debug_msg("igmp query");
  WritablePacket *q = 0;
  click_ip *nip;
  void *igmpbegin;
  igmpv3querie *igp;
  static int id = 1;

  q = Packet::make(sizeof(*nip)+sizeof(*igp));

  // set IP header values...
  nip = reinterpret_cast<click_ip *>(q->data());
  nip->ip_v = 4;
  nip->ip_tos = 0;		
  nip->ip_id = htons(id++);
  nip->ip_off = 0;
  nip->ip_ttl = 1;
  nip->ip_p = 0x02;
  nip->ip_sum = 0;
 
  // this is now being done by the FixIPSource element
  //  nip->ip_src = IPAddress("192.168.30.6");
 
  // destination IPAddress for general queries is 224.0.0.22
  // 224.0.0.1 should work as well but messages are also recieved by hosts,
  // not only routers - useful for debugging
  IPAddress a=IPAddress("0.0.0.0");
  if(source==a.addr())	  nip->ip_dst = IPAddress("224.0.0.22");
  else   nip->ip_dst = IPAddress("224.0.0.1");

  nip->ip_hl = sizeof(click_ip) >> 2;
  q->set_ip_header(nip, nip->ip_hl << 2);


  // now, prepare IGMP header
  igmpbegin = (unsigned char *)q->data()+sizeof(click_ip);
  igp=(igmpv3querie *) igmpbegin;
  igp->type=0x11;
  // the responsecode may vary, the value 1 is ok
  igp->responsecode=1;
  // in a general query the group address is set to 0
  igp->group=group;
  // to create group specific queries just set a group address
  // IGMP capable hosts should respond to this - useful for debugging
  // igp->group=(IPAddress("232.2.2.2").addr());
  
  // querier robustness value (qrv) instructs the host to send all messages 
  // qrv times
  igp->s_and_qrv=0x03; 
  igp->qqic=0x00;

  if(source==a.addr())	igp->no_of_sources=0x00;
  else {
	igp->no_of_sources=htons(0x0001);
	igp->sources[0]=htonl(source.addr());
  }

  igp->checksum=0x0000;
 
  // finish off IP header
  nip->ip_len = htons(q->length());
  nip->ip_sum = click_in_cksum((unsigned char *)nip, nip->ip_hl << 2);
  q->set_dst_ip_anno(IPAddress(nip->ip_dst));
  q->timestamp_anno().set_now();
  SET_FIX_IP_SRC_ANNO(q, true);

  // calculate checksum like described in RFC 1071
  
  unsigned int sum;
  sum=0;
  int count;
  count=sizeof(*igp);
  unsigned short *datapoint=(unsigned short *)q->data()+10;

  while(count > 1) {
	sum += *datapoint++;
	count -= 2;
  }
 
  if(count > 0) sum += *(unsigned char *)datapoint;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

  igp->checksum=~sum;  

  output(1).push(q);  
}

/*******************************************************************************************
 *                                                                                         *
 * run_timer is called continually, it reschedules itself                                  *
 *                                                                                         *
 * for now it calls the function that generates general queries                            *
 * other queries might be added in future releases                                         *
 *                                                                                         *
 *******************************************************************************************/
void
IGMP::run_timer(Timer *)
{
  //  debug_msg("IGMP run timer .X.X.");  
  //  MCastTable->printgroups(true);
  //  query(IPAddress("0.0.0.0"), IPAddress("0.0.0.0"));
  _igmptimer.reschedule_after_msec(INTERVAL);
}

EXPORT_ELEMENT(IGMP)
