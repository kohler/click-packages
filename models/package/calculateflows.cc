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

CalculateFlows::StreamInfo::StreamInfo()
    : have_init_seq(false), have_syn(false), have_fin(false),
      init_seq(0), max_seq(0), max_ack(0), max_live_seq(0), max_loss_seq(0),
      total_packets(0), total_seq(0), loss_events(0), possible_loss_events(0),
      lost_packets(0), lost_seq(0)
{
}

CalculateFlows::LossInfo::LossInfo(const Packet *p, bool eventfiles, const String *outfilenamep)
    : _aggregate(AGGREGATE_ANNO(p))
{
    assert(_aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header())
	   && p->transport_length() >= (int)sizeof(click_udp));
    
    // set initial timestamp
    if (timerisset(&p->timestamp_anno()))
	_init_time = p->timestamp_anno() - make_timeval(0, 1);
    else
	timerclear(&_init_time);

    // plot variables
    _eventfiles = (eventfiles && outfilenamep[0] && outfilenamep[1]);
    _outputdir = "./flown" + String(_aggregate);
    if (_eventfiles)
	system("mkdir -p ./" + _outputdir);

    // set filenames
    for (int i = 0; i < 2; i++)
	_outfilename[i] = _outputdir + "/" + outfilenamep[i];

    // open files if necessary
    if (_eventfiles)
	for (int i = 0; i < 2; i++)
	    if (FILE *f = fopen(_outfilename[i].cc(), "w"))
		fclose(f);
	    else {
		click_chatter("%s: %s", _outfilename[i].cc(), strerror(errno));
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
	    fprintf(f, "Total Bytes Lost = [%u]\n", lost_seq(i));
	    fprintf(f, "Total Packets = [%u]  ", total_packets(i));
	    fprintf(f, "Total Packets Lost = [%u]\n", lost_packets(i));
	    fprintf(f, "Total Loss Events = [%u]\n", loss_events(i));
	    fprintf(f, "Total Possible Loss Events = [%u]\n", ploss_events(i));
	    fprintf(f, "I saw the start(SYN):[%d], I saw the end(FIN):[%d]",
		    _stream[i].have_syn, _stream[i].have_fin);
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
    struct timeval tbstart = time_by_firstseq[paint].find(start_seq);
    struct timeval tbend = time_by_lastseq[paint].find(end_seq);

    if (timerisset(&tbend))
	return tbend;
    else if (timerisset(&tbstart))
	return tbstart;
    else {			// We have a partial retransmission...
	MapInterval &ibtime = inter_by_time[paint];
	for (MapInterval::Iterator iter = ibtime.first(); iter; iter++) {
	    const TimeInterval &tinter = iter.value();
	    if (SEQ_LT(tinter.start_seq, start_seq)
		&& SEQ_GT(tinter.end_seq, start_seq))
		return tinter.time;
	}
	// nothing matches (that cannot be possible unless there is
	// reordering)
	_out_of_order = true;	// set the out-of-order indicator
	printf("Cannot find packet in history of flow %u:%u!:[%u:%u], Possible reordering?\n",
	       _aggregate,
	       paint, 
	       start_seq,
	       end_seq);
	return make_timeval(0, 0);
    }
}

void
CalculateFlows::LossInfo::pre_update_state(const Packet *p)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // set TCP sequence number offsets
    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    if (!_stream[direction].have_init_seq) {
	_stream[direction].init_seq = ntohl(tcph->th_seq);
	_stream[direction].have_init_seq = true;
    }
    if ((tcph->th_flags & TH_ACK) && !_stream[!direction].have_init_seq) {
	_stream[!direction].init_seq = ntohl(tcph->th_ack);
	_stream[!direction].have_init_seq = true;
    }

    // clear out-of-order indicator
    _out_of_order = false;
    
    // save everything else for later
}


void
CalculateFlows::LossInfo::calculate_loss_events2(tcp_seq_t seq, uint32_t seqlen, const struct timeval &time, unsigned paint, ToIPFlowDumps *tipfdp)
{
    assert(paint < 2);
    StreamInfo &stream = _stream[paint];

    // Return if this is new or already-acknowledged data
    if (SEQ_GEQ(seq + 1, stream.max_seq) // Change to +1 for keep alives
				// XXX Should be SEQ_GT ?
	|| SEQ_LEQ(seq + seqlen, stream.max_ack))
	return;

    // XXX What does this mean?
    short num_of_rexmt = rexmt[paint].find(seq);
    if (SEQ_LT(seq, stream.max_loss_seq) && num_of_rexmt <= 0)
	return;

    // XXX Return if packets are out of order
    if (_out_of_order)
	return;

    // If we get this far, it is a new loss event.
    
    rexmt[paint].clear(); // clear previous retransmissions (fresh start for this window)

    // Generate message
    StringAccum sa;
    const char *direction_str = paint ? " < " : " > ";
    struct timeval time_last_sent = Search_seq_interval(seq, seq + seqlen, paint);	
    short num_of_acks = _acks[paint].find(seq);
    bool possible_loss_event; // true if possible loss event
    if (SEQ_LT(seq + seqlen, stream.max_live_seq)) {
	possible_loss_event = false;
	sa << "loss" << direction_str << time_last_sent
	   << ' ' << (seq + seqlen) << ' ' << time
	   << ' ' << stream.max_live_seq << ' ' << num_of_acks;
	stream.loss_events++;
    } else {
	possible_loss_event = true;
	sa << "ploss" << direction_str << time_last_sent
	   << ' ' << seq << ' ' << time
	   << ' ' << seqlen << ' ' << num_of_acks;
	stream.possible_loss_events++;
    }
    tipfdp->add_note(_aggregate, sa.cc());

    if (!possible_loss_event)
	printf("We have a loss Event/CWNDCUT in flow %u at time: [%ld.%06ld] seq:[%u], num_of_acks:%u\n", _aggregate, time.tv_sec, time.tv_usec, seq, num_of_acks);
    else
	printf("We have a POSSIBLE loss Event/CWNDCUT in flow %u at time: [%ld.%06ld] seq:[%u], num_of_acks:%u\n", _aggregate, time.tv_sec, time.tv_usec, seq, num_of_acks);
    _acks[paint].insert(seq, -10000);

    // We just completed a loss event, so reset max_live_seq and max_loss_seq.
    stream.max_live_seq = seq + seqlen;
    if (SEQ_GT(stream.max_seq, stream.max_loss_seq))
	stream.max_loss_seq = stream.max_seq;
}

void
CalculateFlows::LossInfo::calculate_loss(tcp_seq_t seq, uint32_t seqlen, unsigned paint)
{
    assert(paint < 2);
    StreamInfo &stream = _stream[paint];
    
    if (SEQ_LT(stream.max_seq + 1, seq) && stream.total_packets) {
	printf("Possible gap in Byte Sequence flow %u:%u %u - %u\n", _aggregate, paint, stream.max_seq, seq);
    }

    if (SEQ_LT(seq + 1, stream.max_seq) && !_out_of_order) {  // we do a retransmission  (Bytes are lost...)
	MapS &m_rexmt = rexmt[paint];
	m_rexmt.insert(seq, m_rexmt.find(seq) + 1);
	if (SEQ_LT(seq + seqlen, stream.max_seq)) { // are we transmiting totally new bytes also?
	    stream.lost_seq += seqlen;
	} else { // we retransmit something old but partial
	    stream.lost_seq += stream.max_seq - seq;
	}
	stream.lost_packets++;
    }
}

void
CalculateFlows::LossInfo::post_update_state(const Packet *p)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);

    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    StreamInfo &stream = _stream[direction];
    tcp_seq_t seq = ntohl(tcph->th_seq) - stream.init_seq;
    uint32_t seqlen = calculate_seqlen(p->ip_header(), tcph);

    // update counters
    stream.total_packets++;
    stream.total_seq += seqlen;
    
    // mark SYN and FIN packets
    if (tcph->th_flags & TH_SYN) {
	if (stream.have_syn && stream.syn_seq != seq)
	    click_chatter("different SYN seqnos!"); // XXX report error
	else {
	    stream.syn_seq = seq;
	    stream.have_syn = true;
	}
    }
    if (tcph->th_flags & TH_FIN) {
	if (stream.have_fin && stream.fin_seq != seq + seqlen - 1)
	    click_chatter("different FIN seqnos!"); // XXX report error
	else {
	    stream.fin_seq = seq + seqlen - 1;
	    stream.have_fin = true;
	}
    }

    // update max_seq and max_live_seq
    if (SEQ_GT(seq + seqlen, stream.max_seq))
	stream.max_seq = seq + seqlen;
    if (SEQ_GT(seq + seqlen, stream.max_live_seq))
	stream.max_live_seq = seq + seqlen;

    // update acknowledgment information for other half-connection
    StreamInfo &ack_stream = _stream[!direction];
    if (tcph->th_flags & TH_ACK) {
	tcp_seq_t ack = ntohl(tcph->th_ack) - ack_stream.init_seq;
	if (SEQ_GT(ack, ack_stream.max_ack))
	    ack_stream.max_ack = ack;
	// XXX what about -100000 ?
	short &num_acks = _acks[!direction].find_force(ack);
	num_acks++;
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
    MapT &m_tbfirst = time_by_firstseq[paint];
    MapT &m_tblast = time_by_lastseq[paint];
    MapInterval &m_ibtime = inter_by_time[paint];
    
    const click_tcp *tcph = p->tcp_header(); 
    tcp_seq_t seq = ntohl(tcph->th_seq) - _stream[paint].init_seq;
    uint32_t seqlen = calculate_seqlen(p->ip_header(), tcph);

    struct timeval ts = p->timestamp_anno() - _init_time;
    
    if (seqlen > 0) {
	calculate_loss_events2(seq, seqlen, ts, paint, flowdumps); //calculate loss if any
	calculate_loss(seq, seqlen, paint); //calculate loss if any
	m_tbfirst.insert(seq, ts);
	m_tblast.insert(seq + seqlen, ts);
	TimeInterval ti;
	ti.start_seq = seq;
	ti.end_seq = seq + seqlen;
	ti.time = ts;
	m_ibtime.insert(total_packets(paint), ti);
    }

    // update counters, maximum sequence numbers, and so forth
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
		    cpOptional,
		    cpFilename, "filename for output flow1", &_outfilename[0],
		    cpFilename, "filename for output flow2", &_outfilename[1],
		    cpKeywords,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "FLOWDUMPS", cpElement,  "ToIPFlowDumps element pointer (notifier)", &tipfd_element,
		    0) < 0)
        return -1;
    
    AggregateIPFlows *af = 0;
    if (af_element && !(af = (AggregateIPFlows *)(af_element->cast("AggregateIPFlows"))))
	return errh->error("first element not an AggregateIPFlows");
    else if (af)
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
	      if ((loss = new LossInfo(p, true, _outfilename)))
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
CalculateFlows::aggregate_notify(uint32_t aggregate, AggregateEvent event, const Packet *)
{
    if (event == DELETE_AGG) {
	if (LossInfo *tmploss = _loss_map.find(aggregate)) {
	    _loss_map.remove(aggregate);
	    delete tmploss;
	}
    }
}



#if 0
void
CalculateFlows::LossInfo::calculate_loss_events(tcp_seq_t seq, uint32_t seqlen, const struct timeval &time, unsigned paint)
{
    assert(paint < 2);
    double curr_diff;
    short int num_of_acks = acks[paint].find(seq);
    if (SEQ_LT(seq, _max_seq[paint])) { // then we may have a new event.
	if (SEQ_LT(seq, _last_seq[paint])) { // We have a new event ...
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
	if (SEQ_LT(_max_seq[paint], _last_seq[paint])) {
	    _max_seq[paint] = _last_seq[paint];
	}
    }	
    
}
#endif

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)

#include <click/bighashmap.cc>
