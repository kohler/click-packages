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
	if (cp_va_parse(conf, this, errh,
                    cpFilename, "filename for output flow1",&_outfilename[0],
					cpFilename, "filename for output flow2",&_outfilename[1]
					
					,0) < 0)
        return -1;

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
	if (!iph || (iph->ip_p != IP_PROTO_TCP && iph->ip_p != IP_PROTO_UDP) // Sanity check copied from Aggregateflows
	|| !IP_FIRSTFRAG(iph)
	|| p->transport_length() < (int)sizeof(click_udp)) {
	checked_output_push(1, p);
	return 0;
    }
  
  unsigned aggp = AGGREGATE_ANNO(p);
  unsigned paint = PAINT_ANNO(p); // Our Paint
  unsigned cpaint = paint^1;	 // and its complement
  
  IPAddress src(iph->ip_src.s_addr); //for debugging
  IPAddress dst(iph->ip_dst.s_addr); //for debugging
  
  int ip_len = ntohs(iph->ip_len);
  int payload_len = ip_len - (iph->ip_hl << 2);
  timeval ts = p->timestamp_anno(); //the packet timestamp	
	
  StringAccum sa; // just for debugging
    sa << p->timestamp_anno() << ": ";
    sa << "ttl " << (int)iph->ip_ttl << ' ';
    sa << "tos " << (int)iph->ip_tos << ' ';
    sa << "length " << ip_len << ' ';
	 
    switch (iph->ip_p) { 
	 
	 case IP_PROTO_TCP: {
	   int type = 0;// 0 ACK or 1 DACK
	   MapS &m_acks = loss.acks[cpaint];
	   MapT &m_tbfirst = loss.time_by_firstseq[paint];
	   MapT &m_tblast = loss.time_by_lastseq[paint];
   	   MapInterval &m_ibtime = loss.inter_by_time[paint];
	   
	   const click_tcp *tcph = p->tcp_header(); 
       unsigned seq = ntohl(tcph->th_seq); // sequence number of the current packet
       unsigned ack = ntohl(tcph->th_ack); // Acknoledgement sequence number
       unsigned win = ntohs(tcph->th_win); // requested window size
       unsigned seqlen = payload_len - (tcph->th_off << 2); // sequence length 
       int ackp = tcph->th_flags & TH_ACK; // 1 if the packet has the ACK bit
	   if (!loss.rel_seq[paint]) {
	   		loss.rel_seq[paint] = seq;
			seq = 1;
	   }
	   else{
	   		seq = seq - loss.rel_seq[paint];
	   		ack = ack - loss.rel_seq[cpaint];	
	   }
	   
	   
	   
	     	       
	   if (tcph->th_flags & TH_SYN) // Is this a SYN packet?
       		return p;
       if (tcph->th_flags & TH_FIN)	// Is this a FIN packet?
       		return p;
	   if (seqlen > 0) {
		   type=1;
	   	   loss.calculate_loss_events(seq,seqlen,ts,paint); //calculate loss if any
		   loss.calculate_loss(seq, seqlen, paint); //calculate loss if any
   	       print_send_event(paint, ts, seq, (seq+seqlen));
  		   m_tbfirst.insert(seq, ts);
		   m_tblast.insert((seq+seqlen), ts);
		   TimeInterval ti;
		   ti.start_byte = seq;
		   ti.end_byte = seq+seqlen;
		   ti.time = ts;
		   m_ibtime.insert(loss.packets(paint),ti);
	   }
	   
	   if (ackp){ // check for ACK and update as necessary 
	   		loss.set_last_ack(ack,cpaint);
			m_acks.insert(ack, m_acks.find(ack)+1 );
			print_ack_event(cpaint, type, ts, ack);	
			printf("[%u, %u]",ack,m_acks[ack]);
	   }
	   
	   /*for (MapInterval::Iterator iter = m_ibtime.first(); iter; iter++){
	   	TimeInterval *tinter = const_cast<TimeInterval *>(&iter.value());
	   	printf("[%ld.%06ld : %u - %u ]\n",tinter->time.tv_sec, tinter->time.tv_usec, tinter->start_byte, tinter->end_byte);
	    
	   }
	   timeval tv2 = loss.Search_seq_interval(27 ,600, paint);
	   printf("RESULT:[%ld.%06ld]: %u - %u \n",tv2.tv_sec, tv2.tv_usec,27, 600);*/
	   
       loss.inc_packets(paint); // Increment the packets for this flow (forward or reverse)
	   loss.set_total_bytes((loss.total_bytes(paint)+seqlen),paint); //Increase the number bytes transmitted
	   
	   
	   break;
     }
     	 
	 case IP_PROTO_UDP: { // For future use...
       const click_udp *udph = p->udp_header();
       unsigned short srcp = ntohs(udph->uh_sport);
       unsigned short dstp = ntohs(udph->uh_dport);
       unsigned len = ntohs(udph->uh_ulen);
       sa << src << '.' << srcp << " > " << dst << '.' << dstp << ": udp " << len;
       printf("%s",sa.cc());
	   break;
     }
	
	 default :{ // All other packets are not processed
	 	printf("The packet is not a TCP or UDP");
	    sa << src << " > " << dst << ": ip-proto-" << (int)iph->ip_p;
        printf("%s",sa.cc());
		break;
		
		
	 }
	}
	 printf("Timestamp Anno = [%ld.%06ld] " , ts.tv_sec,ts.tv_usec);
	 printf("Sequence Number =[%u,%u]", loss.last_seq(0),loss.last_seq(1));
	 printf("ACK Number =[%u,%u]", loss.last_ack(0),loss.last_ack(1));
	 printf("Total Packets =[%u,%u]", loss.packets(0),loss.packets(1));
	 printf("Total Bytes =[%u,%u]", loss.total_bytes(0),loss.total_bytes(1));
	 printf("Total Bytes Lost=[%u,%u]\n\n", loss.bytes_lost(0),loss.bytes_lost(1));
	
	 return p;
}

void
CalculateFlows::print_ack_event(unsigned paint, int type, timeval tstamp, unsigned ackseq)
{
	FILE *outfile = fopen(_outfilename[paint].cc(), "a");
    if (!outfile) {
        click_chatter("%s: %s", _outfilename[paint].cc(), strerror(errno));
        return;
    }
	if (type == 0){	
		fprintf(outfile,"%ld.%06ld ACK %u\n",tstamp.tv_sec,tstamp.tv_usec,ackseq); 
	}
	else {
		fprintf(outfile,"%ld.%06ld DACK %u\n",tstamp.tv_sec,tstamp.tv_usec,ackseq); 
	}
	if (fclose(outfile)) {
        click_chatter("error closing file!");
    }
}

void
CalculateFlows::
print_send_event(unsigned paint, timeval tstamp, unsigned startseq, unsigned endseq)
{
	FILE *outfile = fopen(_outfilename[paint].cc(), "a");
    if (!outfile) {
        click_chatter("%s: %s", _outfilename[paint].cc(), strerror(errno));
        return;
    }

		fprintf(outfile,"%ld.%06ld SEND %u %u\n",tstamp.tv_sec,tstamp.tv_usec,startseq,endseq); 

	if (fclose(outfile)) {
        click_chatter("error closing file!");
    }
}


ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)


#include <click/bighashmap.cc>
