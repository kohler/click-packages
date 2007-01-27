#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "trw_packet_utils.hh"

// This file is copyright 2005/2006 by the International Computer
// Science Institute.  It can be used for any purposes
// (Berkeley-liscence) as long as this notice remains intact.

// THERE IS NO WARANTEE ON THIS CODE!

// Does this get dropped if we are overcount, even though
// the connection is established?
// Currently, its UDP, TCP SYN (and no ACK),
bool block_policy(Packet *p){
  const click_ip *iph = p->ip_header();
  if(iph->ip_p == IP_PROTO_TCP){
    const click_tcp *tcph = p->tcp_header();
    if( (tcph->th_flags & TH_SYN) &&
	!(tcph->th_flags & TH_ACK)){
      return true;
    }
  } else if(iph->ip_p == IP_PROTO_UDP){
    return true;
  } else {
  }
  return false;
}

// Is this a valid acknowledgement packet
bool valid_ack(Packet *p){
  const click_ip *iph = p->ip_header();
  if(iph->ip_p == IP_PROTO_TCP){
    const click_tcp *tcph = p->tcp_header();
    if( (tcph->th_flags & TH_FIN) ||
	(tcph->th_flags & TH_RST)){
      // TCP FIN & RST are not valid ack, but
      // normal
      return false;
    }
    return true;
  } else if(iph->ip_p == IP_PROTO_UDP){
    return true;
  } else if(iph->ip_p == IP_PROTO_ICMP){
    const click_icmp *icmph = p->icmp_header();
    if (icmph->icmp_type == ICMP_ECHOREPLY) {
      return true;
    }
    return false;
  } else {
    return true;
  }
}


CLICK_ENDDECLS
ELEMENT_PROVIDES(trw_packet_utils)

