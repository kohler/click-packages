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
#include "aggregateipflows.hh"

#include <limits.h>

CalculateFlows::HalfConnectionInfo::HalfConnectionInfo()
    : have_init_seq(false), have_syn(false), have_fin(false),
      init_seq(0), total_packets(0), total_seq(0)
{
}

CalculateFlows::LossInfo::LossInfo(const Packet *p, bool gnuplot, bool eventfiles, const String *outfilenamep)
    : _aggregate(AGGREGATE_ANNO(p))
{
    assert(_aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP
	   && !IP_FIRSTFRAG(p->ip_header())
	   && p->transport_length() >= (int)sizeof(click_udp));
    
    // initialize to empty
    init();

    // set initial timestamp
    if (timerisset(&p->timestamp_anno()))
	_init_time = p->timestamp_anno() - make_timeval(0, 1);
    else
	timerclear(&_init_time);

    // plot variables
    _gnuplot = (gnuplot && outfilenamep[0] && outfilenamep[1]);
    _eventfiles = (eventfiles && outfilenamep[0] && outfilenamep[1]);
    _outputdir = "./flown" + String(_aggregate);
    if (_gnuplot || _eventfiles)
	system("mkdir -p ./" + _outputdir);

    // set filenames
    for (int i = 0; i < 2; i++) {
	_outfilename[i] = _outputdir + "/" + outfilenamep[i];
	_outfilenameg[i] = _outfilename[i] + "_acks.gp";
	_outfilenameg[i+2] = _outfilename[i] + "_xmts.gp";
	_outfilenameg[i+4] = _outfilename[i] + "_levt.gp";
	_outfilenameg[i+6] = _outfilename[i] + "_plevt.gp";
	_outfilenameg[i+8] = _outfilename[i] + "_dacks.gp";
    }

    // open files if necessary
    if (_eventfiles)
	for (int i = 0; i < 2; i++)
	    if (FILE *f = fopen(_outfilename[i].cc(), "w"))
		fclose(f);
	    else {
		click_chatter("%s: %s", _outfilename[i].cc(), strerror(errno));
		return;
	    }
    if (_gnuplot)
	for (int i = 0; i < 10; i++)
	    if (FILE *f = fopen(_outfilenameg[i].cc(), "w"))
		fclose(f);
	    else {
		click_chatter("%s: %s", _outfilenameg[i].cc(), strerror(errno));
		return;
	    }
}

void
CalculateFlows::LossInfo::print_stats()
{
    if (!_eventfiles)
	return;
    for (int i = 0; i < 2; i++) {
	String outfilenametmp = _outfilename[i] + ".stats";
	if (FILE *f = fopen(outfilenametmp.cc(), "w")) {
	    const char *direction = i ? "B->A" : "A->B";
	    fprintf(f, "Flow %u direction from %s \n", _aggregate, direction);
	    fprintf(f, "Total Bytes = [%u]\n", total_seq(i));
	    fprintf(f, "Total Bytes Lost = [%u]\n", bytes_lost(i));
	    fprintf(f, "Total Packets = [%u]  ", total_packets(i));
	    fprintf(f, "Total Packets Lost = [%u]\n", packets_lost(i));
	    fprintf(f, "Total Loss Events = [%u]\n", loss_events(i));
	    fprintf(f, "Total Possible Loss Events = [%u]\n", ploss_events(i));
	    fprintf(f, "I saw the start(SYN):[%d], I saw the end(FIN):[%d]",
		    _hc[i].have_syn, _hc[i].have_fin);
	    fclose(f);
	} else {
	    click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
	    return;
	}
    }
}

struct timeval
CalculateFlows::LossInfo::Search_seq_interval(tcp_seq_t start_seq, tcp_seq_t end_seq, unsigned paint)
{
    assert(paint < 2);
    timeval tbstart = time_by_firstseq[paint].find(start_seq);
    timeval tbend = time_by_lastseq[paint].find(end_seq);
    MapInterval &ibtime = inter_by_time[paint];
    
    if (!tbend.tv_sec && !tbend.tv_usec) {
	if (!tbstart.tv_sec && !tbstart.tv_usec) { // We have a partial retransmission ...
	    for (MapInterval::Iterator iter = ibtime.first(); iter; iter++) {
		TimeInterval *tinter = const_cast<TimeInterval *>(&iter.value());
		if (tinter->start_byte < start_seq && tinter->end_byte > start_seq) {
		    return tinter->time;
		}
		//printf("[%ld.%06ld : %u - %u ]\n",tinter->time.tv_sec, tinter->time.tv_usec, tinter->start_byte, tinter->end_byte);
	    }
	    // nothing matches (that cannot be possible unless there is
	    // reordering)
	    _outoforder_pckt = true; //set the outoforder indicator
	    printf("Cannot find packet in history of flow %u:%u!:[%u:%u], Possible reordering?\n",
		   _aggregate,
		   paint, 
		   start_seq,
		   end_seq);
	    timeval tv = timeval();
	    return tv;
	} else {
	    //printf("Found in Start Byte Hash\n");
	    return tbstart;
	}
	
    } else {
	//printf("Found in End Byte Hash\n");
	return tbend;
    }
    
}

void
CalculateFlows::LossInfo::pre_update_state(const Packet *p)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // set timestamp offset

    // set TCP sequence number offsets
    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    if (!_hc[direction].have_init_seq) {
	_hc[direction].init_seq = ntohl(tcph->th_seq);
	_hc[direction].have_init_seq = true;
    }
    if ((tcph->th_flags & TH_ACK) && !_hc[!direction].have_init_seq) {
	_hc[!direction].init_seq = ntohl(tcph->th_ack);
	_hc[!direction].have_init_seq = true;
    }

    // save everything else for later
}

void
CalculateFlows::LossInfo::post_update_state(const Packet *p)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);

    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    HalfConnectionInfo &hc = _hc[direction];
    tcp_seq_t seq = ntohl(tcph->th_seq);
    uint32_t seqlen = calculate_seqlen(p->ip_header(), tcph);

    // update counters
    hc.total_packets++;
    hc.total_seq += seqlen;
    
    // mark SYN and FIN packets
    if (tcph->th_flags & TH_SYN) {
	if (hc.have_syn && hc.syn_seq != seq)
	    click_chatter("different SYN seqnos!"); // XXX report error
	else {
	    hc.syn_seq = seq;
	    hc.have_syn = true;
	}
    }
    if (tcph->th_flags & TH_FIN) {
	if (hc.have_fin && hc.fin_seq != seq + seqlen - 1)
	    click_chatter("different FIN seqnos!"); // XXX report error
	else {
	    hc.fin_seq = seq + seqlen - 1;
	    hc.have_fin = true;
	}
    }
}

void
CalculateFlows::LossInfo::calculate_loss_events(tcp_seq_t seq, unsigned seqlen, const struct timeval &time, unsigned paint)
{
    assert(paint < 2);
    double curr_diff;
    short int num_of_acks = acks[paint].find(seq);
    if (seq < _max_seq[paint]) { // then we may have a new event.
	if (seq < _last_seq[paint]) { // We have a new event ...
	    timeval time_last_sent = Search_seq_interval(seq, seq + seqlen, paint);	
	    if (_prev_diff[paint] == 0) { // first time
		_prev_diff[paint] = timesub(time, time_last_sent);
		curr_diff = _prev_diff[paint];
	    } else {
		_prev_diff[paint] = (_prev_diff[paint] < 0.000001 ? 0.000001 : _prev_diff[paint]);
		curr_diff = timesub(time,time_last_sent);
		if ((_doubling[paint] == 32) && (fabs(1-curr_diff/_prev_diff[paint]) < 0.1)) {
		    printf("Doubling threshold reached %ld.%06ld \n",time.tv_sec,time.tv_sec);
		} else {
		    if ((fabs(2.-curr_diff/_prev_diff[paint]) < 0.1) && (!(num_of_acks > 3))) {
			if (_doubling[paint] < 1) {
			    _doubling[paint] = _prev_doubling[paint];
			}
			_doubling[paint] = 2*_doubling[paint];
		    }
		    if ((fabs(2.-curr_diff/_prev_diff[paint]) > 0.1) && (!(num_of_acks > 3))) {
			_prev_doubling[paint] = _doubling[paint];
			_doubling[paint] = 0;
		    }
		}
	    }					
	    
	    if (num_of_acks > 3) { //triple dup.
		printf("We have a loss Event/CWNDCUT [Triple Dup] at time: [%ld.%06ld] seq:[%u], num_of_acks:%u \n",
		       time.tv_sec,
		       time.tv_usec,
		       seq,
		       num_of_acks);
		_loss_events[paint]++;
		acks[paint].insert(seq, -10000);
	    } else { 					
		acks[paint].insert(seq, -10000);
		_doubling[paint] = (_doubling[paint] < 1 ? 1 : _doubling[paint]);
		printf ("We have a loss Event/CWNDCUT [Timeout] of %1.0f, at time:[%ld.%06ld] seq:[%u],num_of_acks : %hd\n",
			(log(_doubling[paint])/log(2)),
			time.tv_sec,
			time.tv_usec,
			seq,
			num_of_acks);
		_loss_events[paint]++;
		_prev_diff[paint] = curr_diff;
	    }
	}
    } else { // this is a first time send event
	if (_max_seq[paint] < _last_seq[paint]) {
	    _max_seq[paint] = _last_seq[paint];
	}
    }	
    
}

void
CalculateFlows::LossInfo::calculate_loss_events2(tcp_seq_t seq, unsigned seqlen, const struct timeval &time, unsigned paint, ToIPFlowDumps *tipfdp)
{
    assert(paint < 2);
    double curr_diff;
    short int num_of_acks = acks[paint].find(seq);
    short int  num_of_rexmt = rexmt[paint].find(seq);
    short int possible_loss_event=0; //0 for loss event 1 for possible loss event
    //printf("seq:%u ,rexmt: %d\n",seq , num_of_rexmt);
    if ( ((seq+1) < _max_seq[paint]) && ((seq+seqlen) > _max_ack[paint]) &&  // Change to +1 for keep alives
	 (seq >= _upper_wind_seq[paint] || ( num_of_rexmt > 0 ))) { // then we have a new event.
	//printf("last_seq[%d]=%u \n",paint,seq );
	timeval time_last_sent  = Search_seq_interval(seq ,seq+seqlen, paint);	
	if (!_outoforder_pckt) {
	    rexmt[paint].clear(); // clear previous retransmissions (fresh start for this window)
	    StringAccum sa;
	    String direction = paint ? " < " : " > ";
	    if (_max_wind_seq[paint] > (seq+seqlen)) {
		sa << "loss" << direction << time_last_sent << " " <<
		    (seq+seqlen) << " " << time <<
		    " " << _max_wind_seq[paint] << " " << num_of_acks;
		tipfdp->add_note(_aggregate, sa.cc());
		if (_gnuplot) {
		    FILE *f = fopen(_outfilenameg[paint+4].cc(), "a");
		    fprintf(f, "%f %.1f %f %.1f\n",
			    timeadd(time,time_last_sent)/2.,
			    (_max_wind_seq[paint]+seq+seqlen)/2.,
			    timesub(time,time_last_sent)/2.,
			    (_max_wind_seq[paint]-seq-seqlen)/2.); 
		    fclose(f);
		}
	    } else {
		possible_loss_event = 1; // possible loss event
		sa << "ploss" << direction << time_last_sent << " " << seq << " " << time <<
		    " " << seqlen << " " << num_of_acks  ;
		tipfdp->add_note(_aggregate, sa.cc());
		
		if (_gnuplot) {
		    FILE *f = fopen(_outfilenameg[paint+6].cc(), "a");
		    fprintf(f, "%f %.1f %f %.1f\n",
			    timeadd(time,time_last_sent)/2.,
			    (double)(seq+seqlen/2.),
			    timesub(time,time_last_sent)/2.,
			    seqlen/2.); 
		    fclose(f);
		}	
	    }						
	    if (_prev_diff[paint] == 0) { //first time
		_prev_diff[paint] = timesub(time, time_last_sent);
		curr_diff = _prev_diff[paint];
	    } else {
		_prev_diff[paint] = (_prev_diff[paint] < 0.000001 ? 0.000001 : _prev_diff[paint]);
		curr_diff = timesub(time,time_last_sent);
		if ((_doubling[paint] == 32) && (fabs(1-curr_diff/_prev_diff[paint]) < 0.1)) {
		    printf("Doubling threshold reached %ld.%06ld \n",time.tv_sec,time.tv_sec);
		} else {
		    if ((fabs(2.-curr_diff/_prev_diff[paint]) < 0.1) && (!(num_of_acks > 3))) {
			if (_doubling[paint] < 1) {
			    _doubling[paint] = _prev_doubling[paint];
			}
			_doubling[paint] = 2*_doubling[paint];
		    }
		    if ((fabs(2.-curr_diff/_prev_diff[paint]) > 0.1) && (!(num_of_acks > 3))) {
			_prev_doubling[paint] = _doubling[paint];
			_doubling[paint] = 0;
		    }
		}
	    }					
	    
	    if (num_of_acks > 3) { //triple dup.
		if (!possible_loss_event) {
		    printf("We have a loss Event/CWNDCUT [Triple Dup] in flow %u at time: [%ld.%06ld] seq:[%u], num_of_acks:%u \n",
			   _aggregate,
			   time.tv_sec, 
			   time.tv_usec, 
			   seq,
			   num_of_acks);
		    _loss_events[paint]++;
		} else {
		    printf("We have a POSSIBLE loss Event/CWNDCUT [Triple Dup] in flow %u at time: [%ld.%06ld] seq:[%u], num_of_acks:%u \n",
			   _aggregate,
			   time.tv_sec, 
			   time.tv_usec, 
			   seq,
			   num_of_acks);
		    _p_loss_events[paint]++;
		}
		//	fprintf(outfileg[paint+4],"%ld.%06ld %u\n",
		//			time.tv_sec,time.tv_usec,_max_seq[paint]); 
		acks[paint].insert(seq, -10000);
	    } else { 					
		acks[paint].insert(seq, -10000);
		_doubling[paint] = (_doubling[paint] < 1 ? 1 : _doubling[paint]);
		if (!possible_loss_event) {
		    printf ("We have a loss Event/CWNDCUT [Timeout] of %1.0f in flow %u, at time:[%ld.%06ld] seq:[%u],num_of_acks : %hd\n",
			    (log(_doubling[paint])/log(2)), 
			    _aggregate,
			    time.tv_sec, 
			    time.tv_usec, 
			    seq,
			    num_of_acks); 
		    _loss_events[paint]++;
		} else{
		    printf("We have a POSSIBLE loss Event/CWNDCUT [Timeout] of %1.0f in flow %u, at time:[%ld.%06ld] seq:[%u],num_of_acks : %hd\n",
			   (log(_doubling[paint])/log(2)), 
			   _aggregate,
			   time.tv_sec, 
			   time.tv_usec, 
			   seq,
			   num_of_acks); 
		    _p_loss_events[paint]++;
		}
		//	fprintf(outfileg[paint+4],"%ld.%06ld %u\n",time.tv_sec,time.tv_usec,seq); 	
		//	_prev_diff[paint] = curr_diff;
	    }
	    _max_wind_seq[paint] = seq; //reset the maximum sequence transmitted in this window
	    if (_max_seq[paint] > _upper_wind_seq[paint]) {
		//printf("%u:%u",_last_wind_mseq[paint],_max_seq[paint]);
		_upper_wind_seq[paint] = _max_seq[paint]; // the window for this event loss
	    }
	}
    }
    
}

void
CalculateFlows::LossInfo::calculate_loss(tcp_seq_t seq, unsigned block_size, unsigned paint)
{
    assert(paint < 2);
    
    if (((_max_seq[paint]+1) < seq) && (_max_seq[paint] > 0)) {
	printf("Possible gap in Byte Sequence flow %u:%u %u - %u\n", _aggregate, paint, _max_seq[paint],seq);
    }
    if ((seq+1) < _max_seq[paint] && !_outoforder_pckt) {  // we do a retransmission  (Bytes are lost...)
	MapS &m_rexmt = rexmt[paint];
	//	printf("ok:%u:%u",seq,_max_seq[paint]);
	m_rexmt.insert(seq, m_rexmt.find(seq)+1 );					
	if (seq + block_size < _max_seq[paint]) { // are we transmiting totally new bytes also?
	    _bytes_lost[paint] = _bytes_lost[paint] + block_size;
	    
	} else { // we retransmit something old but partial
	    _bytes_lost[paint] = _bytes_lost[paint] + (_max_seq[paint]-seq);
	    _last_seq[paint] = seq+block_size;  // increase our last sequence to cover new data
	    
	    if (_max_seq[paint] < _last_seq[paint]) {
		_max_seq[paint] = _last_seq[paint];
	    }
	    if (_max_wind_seq[paint] < _last_seq[paint]) {
		_max_wind_seq[paint] = _last_seq[paint];
	    }
	}
	_packets_lost[paint]++;
    } else { // this is a first time send event
	// no loss normal data transfer
	_outoforder_pckt = false; //reset the indicator
	_last_seq[paint] = seq+block_size;  // increase our last sequence to cover new data
	
	if (_max_seq[paint] < _last_seq[paint]) {
	    _max_seq[paint] = _last_seq[paint];
	}
	if (_max_wind_seq[paint] < _last_seq[paint]) {
	    _max_wind_seq[paint] = _last_seq[paint];
	}
	
    }	
    
}

void
CalculateFlows::LossInfo::handle_packet(const Packet *p, ToIPFlowDumps *flowdumps)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // update timestamp and sequence number offsets at beginning of connection
    pre_update_state(p);

    int paint = (PAINT_ANNO(p) & 1);
    MapS &m_acks = acks[!paint];
    MapT &m_tbfirst = time_by_firstseq[paint];
    MapT &m_tblast = time_by_lastseq[paint];
    MapInterval &m_ibtime = inter_by_time[paint];
    
    const click_tcp *tcph = p->tcp_header(); 
    tcp_seq_t seq = ntohl(tcph->th_seq) - _hc[paint].init_seq;
    tcp_seq_t ack = ntohl(tcph->th_ack) - _hc[!paint].init_seq;
    unsigned win = ntohs(tcph->th_win); // requested window size
    unsigned seqlen = calculate_seqlen(p->ip_header(), tcph);
    int ackp = tcph->th_flags & TH_ACK; // 1 if the packet has the ACK bit

    struct timeval ts = p->timestamp_anno() - _init_time;
    
    if (seqlen > 0) {
	if (_eventfiles)
	    print_send_event(paint, ts, seq, (seq+seqlen));
	if (_gnuplot)
	    gplotp_send_event(paint, ts, (seq+seqlen));

	calculate_loss_events2(seq, seqlen, ts, paint, flowdumps); //calculate loss if any
	calculate_loss(seq, seqlen, paint); //calculate loss if any
	m_tbfirst.insert(seq, ts);
	m_tblast.insert((seq+seqlen), ts);
	TimeInterval ti;
	ti.start_byte = seq;
	ti.end_byte = seq + seqlen;
	ti.time = ts;
	m_ibtime.insert(total_packets(paint), ti);
    }

    if (ackp) { // check for ACK and update as necessary
	if (_eventfiles)
	    print_ack_event(!paint, (seqlen > 0), ts, ack);	
	if (_gnuplot)
	    gplotp_ack_event(!paint, (seqlen > 0), ts, ack);	

	if (_max_ack[!paint] < ack)
	    _max_ack[!paint] = ack;
	set_last_ack(ack, !paint);
	m_acks.insert(ack, m_acks.find(ack)+1);
    }

    // update counters and so forth
    post_update_state(p);
}


// CALCULATEFLOWS PROPER

CalculateFlows::CalculateFlows()
    : Element(1, 1), _tipfd(0)
#if CF_PKT
    , _free_pkt(0)
#endif
{
    MOD_INC_USE_COUNT;
}

CalculateFlows::~CalculateFlows()
{
    MOD_DEC_USE_COUNT;
    for (MapLoss::Iterator iter = _loss_map.first(); iter; iter++) {
	LossInfo *losstmp = const_cast<LossInfo *>(iter.value());
	delete losstmp;
    }
#if CF_PKT
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
#endif
}

void
CalculateFlows::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int 
CalculateFlows::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *af_element = 0, *tipfd_element = 0;
    if (cp_va_parse(conf, this, errh,
                    cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    cpElement,  "ToIPFlowDumps element pointer (notifier)", &tipfd_element,
		    cpOptional,
		    cpFilename, "filename for output flow1", &_outfilename[0],
		    cpFilename, "filename for output flow2", &_outfilename[1],
		    0) < 0)
        return -1;
    
    AggregateIPFlows *af;
    if (!af_element || !(af = (AggregateIPFlows *)(af_element->cast("AggregateIPFlows"))))
	return errh->error("first element not an AggregateIPFlows");
    af->add_listener(this);
    
    if (!tipfd_element || !(_tipfd = (ToIPFlowDumps *)(tipfd_element->cast("ToIPFlowDumps"))))
	return errh->error("first element not an ToIPFlowDumps");
    
    return 0;
}

int
CalculateFlows::initialize(ErrorHandler *)
{
    return 0;
}

#if CF_PKT
CalculateFlows::Pkt *
CalculateFlows::new_pkt()
{
    if (!_free_pkt)
	if (Pkt *pkts = new Pkt[1024]) {
	    _pkt_bank.push_back(pkts);
	    for (int i = 0; i < 1024; i++) {
		pkts[i].next = _free_pkt;
		_free_pkt = &pkts[i];
	    }
	}
    if (!_free_pkt)
	return 0;
    else {
	Pkt *p = _free_pkt;
	_free_pkt = p->next;
	p->next = p->prev = 0;
	return p;
    }
}
#endif

Packet *
CalculateFlows::simple_action(Packet *p)
{
    const click_ip *iph = p->ip_header();
    if (!iph || (iph->ip_p != IP_PROTO_TCP && iph->ip_p != IP_PROTO_UDP) // Sanity check copied from AggregateIPFlows
	|| !IP_FIRSTFRAG(iph)
	|| !AGGREGATE_ANNO(p)
	|| p->transport_length() < (int)sizeof(click_udp)) {
	checked_output_push(1, p);
	return 0;
    }
  
    uint32_t aggregate = AGGREGATE_ANNO(p);
  
    IPAddress src(iph->ip_src.s_addr); //for debugging
    IPAddress dst(iph->ip_dst.s_addr); //for debugging
  
    int ip_len = ntohs(iph->ip_len);
    
    StringAccum sa; // just for debugging
    sa << p->timestamp_anno() << ": ";
    sa << "ttl " << (int)iph->ip_ttl << ' ';
    sa << "tos " << (int)iph->ip_tos << ' ';
    sa << "length " << ip_len << ' ';
	 
    switch (iph->ip_p) { 
	 
      case IP_PROTO_TCP: {
	  LossInfo *loss = _loss_map.find(aggregate);
	  if (!loss) {
	      if ((loss = new LossInfo(p, true, true, _outfilename)))
		  _loss_map.insert(aggregate, loss);
	      else {
		  click_chatter("out of memory!");
		  p->kill();
		  return 0;
	      }
	  }
	  loss->handle_packet(p, _tipfd);
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
	
      default: { // All other packets are not processed
	  printf("The packet is not a TCP or UDP");
	  sa << src << " > " << dst << ": ip-proto-" << (int)iph->ip_p;
	  printf("%s",sa.cc());
	  break;
      }
      
    }
    
    return p;
}

void
CalculateFlows::LossInfo::print_ack_event(unsigned paint, int type, const timeval &tstamp, tcp_seq_t ackseq)
{
    assert(paint < 2);
    if (FILE *f = fopen(_outfilename[paint].cc(), "a")) {
	if (type == 0) {
	    fprintf(f, "%ld.%06ld PACK %u\n", tstamp.tv_sec, tstamp.tv_usec,ackseq); 
	} else {
	    fprintf(f, "%ld.%06ld ACK %u\n", tstamp.tv_sec, tstamp.tv_usec,ackseq); 
	}
	fclose(f);
    }
}

void
CalculateFlows::LossInfo::print_send_event(unsigned paint, const timeval &tstamp, tcp_seq_t startseq, tcp_seq_t endseq)
{
    assert(paint < 2);
    if (FILE *f = fopen(_outfilename[paint].cc(), "a")) {
	fprintf(f, "%ld.%06ld SEND %u %u\n", tstamp.tv_sec, tstamp.tv_usec, startseq,endseq);
	fclose(f);
    }
}

void
CalculateFlows::LossInfo::gplotp_ack_event(unsigned paint, int type, const timeval &tstamp, tcp_seq_t ackseq)
{
    assert(paint < 2);
    if (type == 0) {
	FILE *f = fopen(_outfilenameg[paint].cc(), "a");
	fprintf(f, "%ld.%06ld %u\n", tstamp.tv_sec, tstamp.tv_usec, ackseq); 
	fclose(f);
    } else {
	FILE *f = fopen(_outfilenameg[paint+8].cc(), "a");
	fprintf(f, "%ld.%06ld %u\n", tstamp.tv_sec, tstamp.tv_usec,ackseq);
	fclose(f);
    }
}

void
CalculateFlows::LossInfo::gplotp_send_event(unsigned paint, const timeval &tstamp, tcp_seq_t endseq)
{
    FILE *f = fopen(_outfilenameg[paint+2].cc(), "a");
    fprintf(f, "%ld.%06ld %u\n", tstamp.tv_sec, tstamp.tv_usec, endseq);
    fclose(f);
}

void 
CalculateFlows::aggregate_notify(uint32_t aggregate, AggregateEvent event, const Packet *)
{
    if (event == DELETE_AGG) {
	if (LossInfo *tmploss = _loss_map.find(aggregate)) {
	    _loss_map.remove(aggregate);
	    delete tmploss;
	}
    }
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)

#include <click/bighashmap.cc>
