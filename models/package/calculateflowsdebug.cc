// -*- mode: c++; c-basic-offset: 4 -*-
#include <config.h>
#include <click/config.h>

#include "calculateflows.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>

CalculateFlows::CalculateFlows()
    : Element(1, 1)
{
    MOD_INC_USE_COUNT;
}

CalculateFlows::~CalculateFlows()
{
    MOD_DEC_USE_COUNT;
}

void
CalculateFlows::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int 
CalculateFlows::configure(Vector<String> &conf, ErrorHandler *errh)
{
    /*_bidi = false;
    _ports = true;
    return cp_va_parse(conf, this, errh,
		       cpKeywords,
		       "BIDI", cpBool, "bidirectional?", &_bidi,
		       "PORTS", cpBool, "use ports?", &_ports,
		       0);*/
	return 0;
}

int
CalculateFlows::initialize(ErrorHandler *)
{
    return 0;
}

Packet *
CalculateFlows::simple_action(Packet *p)
{
    
	const click_ip *iph = p->ip_header();
	if (!iph || (iph->ip_p != IP_PROTO_TCP && iph->ip_p != IP_PROTO_UDP)
	|| !IP_FIRSTFRAG(iph)
	|| p->transport_length() < (int)sizeof(click_udp)) {
	checked_output_push(1, p);
	return 0;
    }
  	
  unsigned aggp = AGGREGATE_ANNO(p);
  unsigned paint = PAINT_ANNO(p);
  unsigned cpaint = paint^1;
  
  IPAddress src(iph->ip_src.s_addr);
  IPAddress dst(iph->ip_dst.s_addr);
  int ip_len = ntohs(iph->ip_len);
  int payload_len = ip_len - (iph->ip_hl << 2);

  StringAccum sa;
    sa << p->timestamp_anno() << ": ";
    sa << "ttl " << (int)iph->ip_ttl << ' ';
    sa << "tos " << (int)iph->ip_tos << ' ';
    sa << "length " << ip_len << ' ';
	 
    switch (iph->ip_p) {
	 case IP_PROTO_TCP: {
       
	   const click_tcp *tcph = p->tcp_header();
	   unsigned short srcp = ntohs(tcph->th_sport);
	   unsigned short dstp = ntohs(tcph->th_dport);
       unsigned seq = ntohl(tcph->th_seq);
       unsigned ack = ntohl(tcph->th_ack);
       unsigned win = ntohs(tcph->th_win);
       unsigned seqlen = payload_len - (tcph->th_off << 2);
       int ackp = tcph->th_flags & TH_ACK;
 
      /* sa << src << '.' << srcp << " > " << dst << '.' << dstp << ": ";
       if (tcph->th_flags & TH_SYN)
         sa << 'S', seqlen++;
       if (tcph->th_flags & TH_FIN)
         sa << 'F', seqlen++;
       if (tcph->th_flags & TH_RST)
         sa << 'R';
       if (tcph->th_flags & TH_PUSH)
         sa << 'P';
       if (!(tcph->th_flags & (TH_SYN | TH_FIN | TH_RST | TH_PUSH)))
         sa << '.';
 
       sa << ' ' << seq << ':' << (seq + seqlen)
          << '(' << seqlen << ',' << p->length() << ',' << ip_len << ')';
       if (ackp){
         sa << " ack " << ack;
       }
	   sa << " win " << win;
//        printf("Paint: [%u:%u]", paint,cpaint);*/
	    loss.inc_total_packets(paint);
	    loss.set_num_of_bytes((loss.num_of_bytes(paint)+seqlen),paint);
	    loss.set_last_seq((seq+seqlen),paint);
	    if (tcph->th_flags & TH_SYN){
			return p;
		}
		if (!(tcph->th_flags & (TH_SYN | TH_FIN | TH_RST | TH_PUSH))){
       		loss.set_last_ack(ack,cpaint );
			unsigned lost_bytes = loss.calculate_loss(cpaint);
//			printf("Loss:[%d]",lost_bytes);
		}
//		printf("Total Packets =[%u,%u]\n", loss.num_of_bytes(0),loss.num_of_bytes(1));
	   
	   break;
    }
    case IP_PROTO_UDP: {
       const click_udp *udph = p->udp_header();
       unsigned short srcp = ntohs(udph->uh_sport);
       unsigned short dstp = ntohs(udph->uh_dport);
       unsigned len = ntohs(udph->uh_ulen);
       sa << src << '.' << srcp << " > " << dst << '.' << dstp << ": udp " << len;
       break;
    }
	default :{}
	}
//	printf("[%d][%d] %s\n",aggp,paint,sa.cc());
	printf("Sequence Number =[%u,%u]", loss.last_seq(0),loss.last_seq(1));
	printf("ACK Number =[%u,%u]", loss.last_ack(0),loss.last_ack(1));
	printf("Total Packets =[%u,%u]", loss.total_packets(0),loss.total_packets(1));
	printf("Total Bytes =[%u,%u]", loss.num_of_bytes(0),loss.num_of_bytes(1));
	printf("Total Bytes Lost=[%u,%u]\n\n", loss.total_bytes_lost(0),loss.total_bytes_lost(1));
	
	return p;
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)
