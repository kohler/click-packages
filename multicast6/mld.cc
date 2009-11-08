/*
 * MLD.{cc,hh} -- MLD processing element
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
#include "mld.hh"
#include "ip6multicasttable.hh"
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
#include <click/confparse.hh>
#include "debug.hh"

MLD::MLD(): _timer(this)
{
}

MLD::~MLD()
{
}

/*******************************************************************************************
 *                                                                                         *
 * configure: get name of MulticastTable element to access datastructures                  *
 *                                                                                         *
 *******************************************************************************************/
int
MLD::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("wrong number of arguments; expected 'MLD(IP6MulticastTable element)'");

  // get Multicast6 element
  Element *e = cp_element(conf[0], this, errh);
  if (!e) {
    return -1;
  }
  else {
	MCastTable = (IP6MulticastTable *)e->cast("IP6MulticastTable");

	return 0;
  }
}

/*******************************************************************************************
 *                                                                                         *
 * initialization: initialize timer                                                        *
 *                                                                                         *
 *******************************************************************************************/
int MLD::initialize(ErrorHandler *errh)
{
  // debug_msg("MLD: mld initil");
  _timer.initialize(this);
  _timer.schedule_after_msec(QUERY_INTERVAL);
  // at startup the router assumes he is the only MLDv2 router in its subnet
  querierstate=true;

  // ** for performance tests, add a number of groups and receivers ***
  // IP6Address group;
  //IP6Address recv=(IP6Address(0));
  // IP6Address src;
  //  recv=IP6Address("3ffe:1001:7d0:4::3");

  /**************************** add groups to measure performance ****************/
  /*  for(unsigned int i=1; i < 80001; i++)
	{
	  MCastTable->addgroup(IP6Address(i));
	  MCastTable->joingroup(IP6Address(i), IP6Address(~i));  
	}

  group=IP6Address("FF33::8000:8000");
  MCastTable->addgroup(group);


  for(unsigned int i=1; i < 10; i++)
	{
	  	  MCastTable->joingroup(IP6Address(i), group);  
	}

  group=IP6Address("FF33::8000:8001");
  MCastTable->addgroup(group);


  for(unsigned int i; i < 10; i++)
	{
	  	  MCastTable->joingroup(IP6Address(i), group);  
	}

  group=IP6Address("FF33::8000:8002");
  MCastTable->addgroup(group);


  for(unsigned int i; i < 10; i++)
	{
	  	  MCastTable->joingroup(IP6Address(i), group);  

	}
  */
  return 0;
}

/*******************************************************************************************
 *                                                                                         *
 * simpleaction: each arriving packet is examined here                                     *
 *                                                                                         *
 *******************************************************************************************/
Packet *
MLD::simple_action(Packet *p)
{
  // get header addresses
  const click_ip6 *ip = (const click_ip6 *)p->ip6_header();
  hopbyhopheader *hopbyhop;
  // goto offset.
  void *mldmessage = (void *) ((char *)p->data() + sizeof(*ip) + sizeof(*hopbyhop));
  
  
  /* this variable saves the MLD message ID
   * the following IDs are reckognized 
   * 130 listener query
   * 131 MLDv1 listener report
   * 132 MLDv1 listener done
   * 143 listener report (linux kernel version < 2.6.6 use value 206)
   */

  // some counters are needed to access datastructure
  unsigned short grouprecord_counter;
  short source_counter;
  // variable holding ICMPv6 checksum
  unsigned short chk;

  switch(*(char *)mldmessage)
	{
	case 130:
	  // (XXX) this has to be filled with some action
	  v2query = (mldv2querie *) mldmessage;
	  chk=htons(in6_cksum(&ip->ip6_src, &ip->ip6_dst,
			      htons(sizeof(*v2query)), 
			      0x3a,
			      v2query->checksum,
			      (unsigned char *)v2query,
			      htons(sizeof(*v2query))));
	  if(chk!=v1report->checksum)
		{
		  debug_msg("MLD: incorrect checksum, MLD message discarded!");
		  break;
		}
	  else {
		debug_msg("MLD: MLD query");
		// if src-ip-address < my IP address switch querierstate to false
		break;
	  }
	  break;
	  
	case 131:
	  
	  //	  debug_msg("MLD: MLDv1 listener report");
	  v1report = (mldv1message *) mldmessage;
	  
	  // check, whether the messages checksum is correct or not

	  chk=htons(in6_cksum(&ip->ip6_src,
			      &ip->ip6_dst,
			      htons(sizeof(*v1report)),
			      0x3a, v1report->checksum,
			      (unsigned char *)v1report,
			      htons(sizeof(*v1report))));
	  if(chk!=v1report->checksum)
		{
		  debug_msg("MLD: incorrect checksum, MLD message discarded!");
		  break;
		}
	  else {
		MCastTable->addgroup(IP6Address(v1report->group));
		MCastTable->joingroup(IP6Address(ip->ip6_src), IP6Address(v1report->group));  	  
		if ( IP6Address(v1report->group).matches_prefix(IP6Address("FF70::0"),
								IP6Address("FFF0::0")) )     {
		  MCastTable->addsource(IP6Address(ip->ip6_src),
					IP6Address(v1report->group),
					IP6Address(extract_rp(IP6Address(v1report->group))));
		}
		break;
	  }
	  
	case 132:
	  //	  debug_msg("MLD: MLDv1 listener done");
	  v1report = (mldv1message *) mldmessage;
	  chk=htons(in6_cksum(&ip->ip6_src, &ip->ip6_dst,
			      htons(sizeof(*v1report)),
			      0x3a, v1report->checksum,
			      (unsigned char *)v1report,
			      htons(sizeof(*v1report))));
	  if(chk!=v1report->checksum)
		{
		  debug_msg("MLD: incorrect checksum, MLD message discarded!");
		  break;
		}
	  else {
		//		MCastTable->addgroup(IP6Address(v1report->group));
		if ( IP6Address(v1report->group).matches_prefix(IP6Address("FF70::0"),
								IP6Address("FFF0::0")) )     {
		  MCastTable->delsource(IP6Address(ip->ip6_src),
					IP6Address(v1report->group),
					IP6Address(extract_rp(IP6Address(v1report->group))));
		}
		MCastTable->leavegroup(IP6Address(ip->ip6_src), IP6Address(v1report->group)); 
	  } 	  
	  break;
	  
	case 143:
	  report = (mldv2report *) mldmessage;
	  chk=htons(in6_cksum(&ip->ip6_src, &ip->ip6_dst,
			      htons(ntohs(ip->ip6_plen)-sizeof(*hopbyhop)),
			      0x3a, report->checksum,
			      (unsigned char *)report,
			      htons(ntohs(ip->ip6_plen)-sizeof(*hopbyhop))));
	  if(chk!=report->checksum)
		{
		  debug_msg("MLD: incorrect checksum, MLDv2 message discarded!");
		}
	  else {
		for(grouprecord_counter=0; grouprecord_counter < ntohs(report->no_of_grouprecords); grouprecord_counter++)
		  {
			switch(report->grouprecords[grouprecord_counter].type) {
			case 0x01: 
			  // debug_msg("MLD: MLDv2 include");
			  // MODE_IS_INCLUDE, generated by hosts, ignored by router
			  break; 
			case 0x02:
			  // debug_msg("MLD: MLDv2 exclude");
			  // MODE_IS_EXCLUDE, generated by hosts, ignored by router
			  break;
			case 0x03:
			  debug_msg("MLD: CHANGE_TO_INCLUDE_MODE");
			  change_to_include_mode(IP6Address(ip->ip6_src),
						 IP6Address(report->grouprecords[grouprecord_counter].multicast_address),
						 ntohs(report->grouprecords[grouprecord_counter].no_of_sources),
						 grouprecord_counter);
			  
			  break;
			case 0x04:
			  debug_msg("MLD: CHANGE_TO_EXCLUDE_MODE");
			  MCastTable->addgroup(IP6Address(report->grouprecords[grouprecord_counter].multicast_address));
			  change_to_exclude_mode(IP6Address(ip->ip6_src),
						 IP6Address(report->grouprecords[grouprecord_counter].multicast_address),
						 ntohs(report->grouprecords[grouprecord_counter].no_of_sources), grouprecord_counter);
			  
			  break;
			case 0x05:
			  debug_msg("MLD: ALLOW_NEW_SOURCES");
			  allow_new_sources(IP6Address(ip->ip6_src),
					    IP6Address(report->grouprecords[grouprecord_counter].multicast_address),
					    ntohs(report->grouprecords[grouprecord_counter].no_of_sources), grouprecord_counter );
			  
			  break;
			case 0x06:
			  debug_msg("MLD: BLOCK_OLD_SOURCES");
			  block_old_sources(IP6Address(ip->ip6_src),
					    IP6Address(report->grouprecords[grouprecord_counter].multicast_address),
					    ntohs(report->grouprecords[grouprecord_counter].no_of_sources),
					    grouprecord_counter );
			  
			  break;
			default:
			  debug_msg("MLD: Unknown type in MLD grouprecord");
			}
		  } 
		break;
	  }
	default:
	  debug_msg("MLD: unknown MLD message %x", (char *)mldmessage);
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
MLD::change_to_exclude_mode(IP6Address recv,
			    IP6Address group,
			    unsigned short no_of_sources,
			    unsigned short groupcounter) 
{
  MCastTable->joingroup(recv, group);  
  MCastTable->set_receiver_mode(recv, group, EXCLUDEMODE);

  if ( no_of_sources==0 && group.matches_prefix(IP6Address("FF70::0"), IP6Address("FFF0::0")) )     {
      MCastTable->addsource(IP6Address(recv), IP6Address(group), IP6Address(extract_rp(group)));
      debug_msg("MLD: mld calls mcasttable addsource");
    }

  for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->addsource(IP6Address(recv),
				IP6Address(group),
				IP6Address(report->grouprecords[groupcounter].sources[source_counter]));
	}
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
MLD::change_to_include_mode(IP6Address recv,
			    IP6Address group,
			    unsigned short no_of_sources,
			    unsigned short groupcounter) 
{
  MCastTable->joingroup(recv, group);  
  MCastTable->set_receiver_mode(recv, group, INCLUDEMODE);

  for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->addsource(IP6Address(recv),
				IP6Address(group),
				IP6Address(report->grouprecords[groupcounter].sources[source_counter]));
	}
  if(no_of_sources == 0) MCastTable->leavegroup(recv, group);
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
MLD::allow_new_sources(IP6Address recv,
		       IP6Address group,
		       unsigned short no_of_sources,
		       unsigned short groupcounter) 
{

  MCastTable->joingroup(recv, group);

  MCastTable->set_receiver_mode(recv, group, INCLUDEMODE);
 
  for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->addsource(IP6Address(recv),
				IP6Address(group),
				IP6Address(report->grouprecords[groupcounter].sources[source_counter]));
	}
}

/*******************************************************************************************
 *                                                                                         *
 * blockoldsources is called after the arrival of type 6 group records                     *
 *                                                                                         *
 * it deletes all unwanted source addresses from the multicasttable                        *
 *                                                                                         *
 *******************************************************************************************/
bool
MLD::block_old_sources(IP6Address recv,
		       IP6Address group,
		       unsigned short no_of_sources,
		       unsigned short groupcounter) 
{
   for(unsigned int source_counter=0; source_counter!=no_of_sources; source_counter++)
	{
	  MCastTable->delsource(recv,
				group,
				IP6Address(report->grouprecords[groupcounter].sources[source_counter]));
	}
}

/*******************************************************************************************
 *                                                                                         *
 * query is called to generate query messages. all arriving changes of state of an         *
 * interface are followed by a group/source specific query                                 *
 *                                                                                         *
 *                                                                                         *
 *******************************************************************************************/
void
MLD::generalquery()
{
  debug_msg("MLD: generalquery");
  WritablePacket *q = 0;

  click_ip6 *nip;
  void *mldbegin;
  mldv2querie *igp;
  hopbyhopheader *hopbyhop;

  q = Packet::make(sizeof(*nip)+sizeof(*hopbyhop)+sizeof(*igp));

  nip = reinterpret_cast<click_ip6 *>(q->data());
  hopbyhop=(hopbyhopheader *) (q->data() + sizeof(*nip));
  igp=(mldv2querie *)((char *)hopbyhop + sizeof(*hopbyhop));;

  nip->ip6_flow = 0;		// set flow to 0 (includes version)
  nip->ip6_v = 6;		// then set version to 6
  nip->ip6_plen=htons(sizeof(*igp)+sizeof(*hopbyhop));
  nip->ip6_nxt=0x00; //i.e. protocal: hop-by-hop message
  nip->ip6_hlim=0x01; //kill at next router
  nip->ip6_src = IP6Address("fe80::204:23ff:fe45:9d71");
 
  nip->ip6_dst = IP6Address("ff02::1");
  SET_DST_IP6_ANNO(q, IP6Address("ff02::1"));
  hopbyhop->type=0x3a;  //MLD router alert
  hopbyhop->length=0;
  hopbyhop->parameter=0x0502;

  igp->type=130;
  igp->code=0x00;
  igp->checksum=0x0000;
  igp->responsecode=0x01;
  igp->reserved=0;
  igp->group=IP6Address("::"); 
  igp->res_and_s_and_qrv=0x03; 
  igp->qqic=0x00;
  igp->no_of_sources=0x00;

  output(1).push(q);  
}

/*******************************************************************************************
 *                                                                                         *
 * extract_RP extracts embedded RP address from multicast group address                    *
 * see RFC3956 for details                                                                 *
 *                                                                                         *
 *                                                                                         *
 *******************************************************************************************/
IP6Address 
MLD::extract_rp(IP6Address group)
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

/*******************************************************************************************
 *                                                                                         *
 * run_timer is called continually, it reschedules itself                                  *
 *                                                                                         *
 * for now it calls the function that generates general queries                            *
 * other queries might be added in future releases                                         *
 *                                                                                         *
 *******************************************************************************************/
void
MLD::run_timer(Timer *)
{
  debug_msg("MLD: run timer");  
  //  MCastTable->printgroups(true);
  if(querierstate) {
    //	generalquery();
	_timer.reschedule_after_msec(QUERY_INTERVAL);
  }
  else {
	// see RFC 3810 for the correct time value... 
	_timer.reschedule_after_msec( (QUERY_INTERVAL*2) + (QUERY_RESPONSE_INTERVAL/2) );
  }
}

EXPORT_ELEMENT(MLD)
