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
	 for (MapLoss::Iterator iter = loss_map.first(); iter; iter++){
	   	LossInfo *losstmp = const_cast<LossInfo *>(iter.value());
	   	delete losstmp;
	 }
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
                    cpElement,  "AggregateFlows element pointer", &af,
					cpFilename, "filename for output flow1",&outfilename[0],
					cpFilename, "filename for output flow2",&outfilename[1]
					
					,0) < 0)
        return -1;
		af->add_listener(this); // this is a handler to AggregateFlows Element
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
 	   loss = loss_map.find(aggp);
	   MapS &m_acks = loss->acks[cpaint];
	   MapT &m_tbfirst = loss->time_by_firstseq[paint];
	   MapT &m_tblast = loss->time_by_lastseq[paint];
   	   MapInterval &m_ibtime = loss->inter_by_time[paint];
	   
	   
	   const click_tcp *tcph = p->tcp_header(); 
       unsigned seq = ntohl(tcph->th_seq); // sequence number of the current packet
       unsigned ack = ntohl(tcph->th_ack); // Acknoledgement sequence number
       unsigned win = ntohs(tcph->th_win); // requested window size
       unsigned seqlen = payload_len - (tcph->th_off << 2); // sequence length 
       int ackp = tcph->th_flags & TH_ACK; // 1 if the packet has the ACK bit

	   if ( (loss->init_time.tv_usec == 0) && (loss->init_time.tv_sec == 0) ){ 
	  	// unsigned short sport = ntohs(tcph->th_sport);
  	  	// unsigned short dport = ntohs(tcph->th_dport);
  	  	// printf("%u: %s:%d->%s:%d\n",aggp,src.unparse().cc(),sport,dst.unparse().cc(),dport);
	  	loss->init_time = ts;
		ts.tv_sec = 1;
	   	ts.tv_usec = 0;
	   }
	   else{
	   	ts.tv_sec++;
		ts = ts - loss->init_time;
		//if ((ts.tv_usec == 0) && (ts.tv_sec == 0)){
		//	ts.tv_usec = 1;
	   	//}
	   }			
	   //printf("%u,%u[%ld.%06ld]:[%ld.%06ld] \n",aggp,paint,loss->init_time.tv_sec,loss->init_time.tv_usec,ts.tv_sec,ts.tv_usec);
	   
	   // converting the Sequences from Absolute to Relative
	   if ( !loss->init_seq[paint]){ 
	   	loss->init_seq[paint] = seq;
	   	seq = 0;
	   }
	   else{
	   	seq = seq - loss->init_seq[paint];
	   }
		 
	   if (tcph->th_flags & TH_SYN){ // Is this a SYN packet?
       		loss->has_syn[paint] = 1;
			return p;
       }
	   if (tcph->th_flags & TH_FIN){	// Is this a FIN packet?
       		loss->has_fin[paint] = 1;
			return p;
	   }  
	   if (seqlen > 0) {
		   type=1;
	   	   loss->calculate_loss_events2(seq,seqlen,ts,paint); //calculate loss if any
		   loss->calculate_loss(seq, seqlen, paint); //calculate loss if any
   	       if (loss->eventfiles){
		   	print_send_event(paint, ts, seq, (seq+seqlen));
		   }
		   if (loss->gnuplot){
		   	gplotp_send_event(paint, ts, (seq+seqlen));
  		   }
		   m_tbfirst.insert(seq, ts);
		   m_tblast.insert((seq+seqlen), ts);
		   TimeInterval ti;
		   ti.start_byte = seq;
		   ti.end_byte = seq+seqlen;
		   ti.time = ts;
		   m_ibtime.insert(loss->packets(paint),ti);
	   }
	   
	   if (ackp){ // check for ACK and update as necessary 
	   	   // converting the Sequences from Absolute to Relative (we need that
		   // for acks also!)
		   if ( !loss->init_seq[cpaint]){
	   	   	loss->init_seq[cpaint] = ack;
			ack = 0;
		   }
	   	   else{
		   	ack = ack - loss->init_seq[cpaint];
		   }	
			
			loss->set_last_ack(ack,cpaint);
			m_acks.insert(ack, m_acks.find(ack)+1 );
    	    if (loss->eventfiles){
				print_ack_event(cpaint, type, ts, ack);	
			}
			if (loss->gnuplot){
		    	gplotp_ack_event(cpaint, ts, ack);	
			//printf("[%u, %u]",ack,m_acks[ack]);
	   		}
	   }
	   
	/* for (MapS::Iterator iter = m_acks.first(); iter; iter++){
	   	short int *value = const_cast<short int *>(&iter.value());
		const unsigned *temp = &m_acks.key_of_value(value);
	   	printf("%u:%hd \n",*temp,*value);
	    
	   }
	   timeval tv2 = loss->Search_seq_interval(27 ,600, paint);
	   printf("RESULT:[%ld.%06ld]: %u - %u \n",tv2.tv_sec, tv2.tv_usec,27, 600);*/
	   
       loss->inc_packets(paint); // Increment the packets for this flow (forward or reverse)
	   loss->set_total_bytes((loss->total_bytes(paint)+seqlen),paint); //Increase the number bytes transmitted
	 //  printf("[%u] %u:%u:%u\n",paint,loss->packets(paint),loss->total_bytes(paint),seq);
	   
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
	 /*if (aggp == 905){
	 printf("Timestamp Anno = [%ld.%06ld] " , ts.tv_sec,ts.tv_usec);
	 printf("Sequence Number =[%u,%u]", loss->last_seq(0),loss->last_seq(1));
	 printf("ACK Number =[%u,%u]", loss->last_ack(0),loss->last_ack(1));
	 printf("Total Packets =[%u,%u]", loss->packets(0),loss->packets(1));
	 printf("Total Bytes =[%u,%u]", loss->total_bytes(0),loss->total_bytes(1));
	 printf("Total Bytes Lost=[%u,%u]\n\n", loss->bytes_lost(0),loss->bytes_lost(1));
	 }*/
	 return p;
}

void
CalculateFlows::
print_ack_event(unsigned paint, int type, timeval tstamp, unsigned ackseq)
{
	
	loss->outfile[paint] = fopen(loss->outfilename[paint].cc(), "a");
	if (type == 0){	
		fprintf(loss->outfile[paint],"%ld.%06ld PACK %u\n",tstamp.tv_sec,tstamp.tv_usec,ackseq); 
	}
	else {
		fprintf(loss->outfile[paint],"%ld.%06ld ACK %u\n",tstamp.tv_sec,tstamp.tv_usec,ackseq); 
	}
	//fflush(loss->outfile[paint]);
	if (fclose(loss->outfile[paint])){ 
   		click_chatter("error closing file!");
	}
	
}

void
CalculateFlows::
print_send_event(unsigned paint, timeval tstamp, unsigned startseq, unsigned endseq)
{
	loss->outfile[paint] = fopen(loss->outfilename[paint].cc(), "a");
	fprintf(loss->outfile[paint],"%ld.%06ld SEND %u %u\n",tstamp.tv_sec,tstamp.tv_usec,startseq,endseq); 
//	fflush(loss->outfile[paint]);
	if (fclose(loss->outfile[paint])){ 
   		click_chatter("error closing file!");
	}

}

void
CalculateFlows::
gplotp_ack_event(unsigned paint, timeval tstamp, unsigned ackseq)
{
	loss->outfileg[paint] = fopen(loss->outfilenameg[paint].cc(), "a");
	fprintf(loss->outfileg[paint],"%ld.%06ld %u\n",tstamp.tv_sec,tstamp.tv_usec,ackseq); 
	//fflush(loss->outfileg[paint]);
	if (fclose(loss->outfileg[paint])){ 
   		click_chatter("error closing file!");
	}

}

void
CalculateFlows::
gplotp_send_event(unsigned paint, timeval tstamp, unsigned endseq)
{
	loss->outfileg[paint+2] = fopen(loss->outfilenameg[paint+2].cc(), "a");
	fprintf(loss->outfileg[paint+2],"%ld.%06ld %u\n",tstamp.tv_sec,tstamp.tv_usec,endseq); 
	//fflush(loss->outfileg[paint+2]);
	if (fclose(loss->outfileg[paint+2])){ 
   		click_chatter("error closing file!");
	}

}

void 
CalculateFlows::
aggregate_notify(uint32_t aggregate_ID,
                 AggregateEvent event /* can be NEW_AGG or DELETE_AGG */,
                 const Packet *packet /* null for DELETE_AGG */){
//	printf("ok1 ---->%d %d\n", aggregate_ID, event);
	if (event == NEW_AGG){	
		LossInfo *tmploss = new LossInfo(outfilename,aggregate_ID, 0, 0) ;
		loss_map.insert(aggregate_ID, tmploss);
	}
	
	else if (event == DELETE_AGG){
		LossInfo *tmploss = loss_map.find(aggregate_ID);	
		loss_map.remove(aggregate_ID);
		delete tmploss;
	}
}	


ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)


#include <click/bighashmap.cc>
