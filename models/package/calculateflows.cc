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
      have_ack_bounce(false),
      init_seq(0), max_seq(0), max_ack(0), max_live_seq(0), max_loss_seq(0),
      total_packets(0), total_seq(0),
      loss_events(0), possible_loss_events(0), false_loss_events(0),
      event_id(0),
      lost_packets(0), lost_seq(0),
      pkt_head(0), pkt_tail(0),
      loss_type(NO_LOSS)
{
}

void
CalculateFlows::StreamInfo::insert(Pkt *k)
{
    // check for empty list
    if (!pkt_tail) {
	assert(!pkt_head);
	pkt_head = pkt_tail = k;
	k->type = Pkt::ALL_NEW;
	return;
    }

    // check that timestamp makes sense
    if (k->timestamp < pkt_tail->timestamp) {
	click_chatter("timestamp confusion");
	k->timestamp = pkt_tail->timestamp;
    }

    // insert packet into list
    k->prev = pkt_tail;
    k->next = 0;
    k->prev->next = pkt_tail = k;

    // check for retransmissions
    if (SEQ_GEQ(k->seq, max_seq)) {
	k->type = Pkt::ALL_NEW;
	return;
    }

    // Otherwise, it is a reordering, or possibly a retransmission.
    // Find the most recent retransmission of overlapping data.
    Pkt *x = pkt_tail->prev;
    while (k->type == Pkt::UNKNOWN && x) {
	if (k->seq == x->seq && k->last_seq == x->last_seq) {
	    // complete retransmission
	    k->type = Pkt::REXMIT;
	    k->rexmit_pkt = x;
	} else if (k->seq == x->seq) {
	    // partial retransmission
	    k->type = Pkt::PARTIAL_REXMIT;
	    k->rexmit_pkt = x;
	} else if (x->type == Pkt::ALL_NEW && SEQ_LEQ(x->last_seq, k->seq))
	    // reordering
	    k->type = Pkt::REORDERED;
	else if ((SEQ_LEQ(x->seq, k->seq) && SEQ_LT(k->seq, x->last_seq))
		 || (SEQ_LT(x->seq, k->last_seq) && SEQ_LEQ(k->last_seq, x->last_seq))) {
	    // odd partial retransmission
	    k->type = Pkt::ODD_REXMIT;
	    k->rexmit_pkt = x;
	} else
	    x = x->prev;
    }
    
    // If we ran out of packets, it's a reordering.
    if (k->type == Pkt::UNKNOWN)
	k->type = Pkt::REORDERED;
}

CalculateFlows::Pkt *
CalculateFlows::StreamInfo::find_acked_pkt(tcp_seq_t ack, const struct timeval &timestamp)
{
    // XXX start from the middle?
    Pkt *potential_answer = 0;
    for (Pkt *k = pkt_tail; k; k = k->prev) {
	if (k->last_seq == ack) {
	    if (k->type == Pkt::REXMIT
		&& have_ack_bounce
		&& timestamp - k->timestamp < min_ack_bounce)
		potential_answer = k;
	    else
		return k;
	} else if (SEQ_LT(k->seq, ack) && SEQ_LEQ(ack, k->last_seq))
	    // partial ack
	    potential_answer = k;
    }
    return potential_answer;
}

void
CalculateFlows::StreamInfo::output_loss(uint32_t aggregate, unsigned direction, CalculateFlows *cf)
{
    assert(direction < 2);
    if (loss_type != NO_LOSS) {
	const char *direction_str = (direction ? " < " : " > ");
	const char *loss_type_str;
	if (loss_type == LOSS) {
	    loss_type_str = "loss";
	    loss_events++;
	} else if (loss_type == POSSIBLE_LOSS) {
	    loss_type_str = "ploss";
	    possible_loss_events++;
	} else {
	    assert(loss_type == FALSE_LOSS);
	    loss_type_str = "floss";
	    false_loss_events++;
	}
	if (cf->flow_dumps()) {
	    StringAccum sa;
	    sa << loss_type_str << direction_str << loss_time
	       << ' ' << loss_seq << ' ' << loss_end_time
	       << ' ' << loss_last_seq << ' ' << '0'; // XXX nacks
	    cf->flow_dumps()->add_note(aggregate, sa.take_string());
	}
	if (cf->loss_file())
	    fprintf(cf->loss_file(), "%s %u%s%ld.%06ld %u %ld.%06ld %u\n",
		    loss_type_str, aggregate, direction_str,
		    loss_time.tv_sec, loss_time.tv_usec, loss_seq,
		    loss_end_time.tv_sec, loss_end_time.tv_usec, loss_last_seq);
	loss_type = NO_LOSS;
    }
}


// LOSSINFO

CalculateFlows::LossInfo::LossInfo(const Packet *p)
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
}

void
CalculateFlows::LossInfo::kill(CalculateFlows *cf)
{
    _stream[0].output_loss(_aggregate, 0, cf);
    _stream[1].output_loss(_aggregate, 1, cf);
    cf->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    cf->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    if (cf->stat_file()) {
	fprintf(cf->stat_file(), "%u 0\t%u\t%u\t%u\t%u\t%u\n",
		_aggregate, _stream[0].total_packets, _stream[0].total_seq,
		_stream[0].loss_events, _stream[0].possible_loss_events,
		_stream[0].false_loss_events);
	fprintf(cf->stat_file(), "%u 1\t%u\t%u\t%u\t%u\t%u\n",
		_aggregate, _stream[1].total_packets, _stream[1].total_seq,
		_stream[1].loss_events, _stream[1].possible_loss_events,
		_stream[1].false_loss_events);
    }
    delete this;
}

CalculateFlows::Pkt *
CalculateFlows::LossInfo::pre_update_state(const Packet *p, CalculateFlows *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // set TCP sequence number offsets
    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    StreamInfo &stream = _stream[direction];
    if (!stream.have_init_seq) {
	stream.init_seq = ntohl(tcph->th_seq);
	stream.have_init_seq = true;
    }
    StreamInfo &ack_stream = _stream[!direction];
    if ((tcph->th_flags & TH_ACK) && !ack_stream.have_init_seq) {
	ack_stream.init_seq = ntohl(tcph->th_ack);
	ack_stream.have_init_seq = true;
    }

    // introduce a Pkt
    Pkt *k = parent->new_pkt();
    if (!k)
	return 0;
    const click_ip *iph = p->ip_header();
    k->init(ntohl(tcph->th_seq) - stream.init_seq, calculate_seqlen(iph, tcph),
	    p->timestamp_anno() - _init_time, stream.event_id);
    stream.insert(k);
    
    // save everything else for later
    return k;
}


void
CalculateFlows::LossInfo::calculate_loss_events2(Pkt *k, unsigned direction, CalculateFlows *parent)
{
    assert(direction < 2);
    StreamInfo &stream = _stream[direction];
    tcp_seq_t seq = k->seq;
    tcp_seq_t last_seq = k->last_seq;

    // Return if this is new or already-acknowledged data
    if (SEQ_GEQ(seq, stream.max_seq))
	return;

    // Return if this retransmission is due to a previous loss event
    if (k->event_id != k->rexmit_pkt->event_id)
	return;

    // Return if this is a keepalive (XXX)
    if (stream.max_seq == k->last_seq && k->last_seq == k->seq + 1)
	return;
    
    // Return if packets are out of order
    if (k->type == Pkt::REORDERED)
	return;

    // If we get this far, it is a new loss event.
    
    // Update the event ID
    stream.event_id++;
    k->event_id = stream.event_id;

    // Store information about the loss event
    if (stream.loss_type != NO_LOSS) // get rid of the last loss event
	stream.output_loss(_aggregate, direction, parent);
    if (SEQ_GT(stream.max_ack, seq))
	stream.loss_type = FALSE_LOSS;
    else if (SEQ_GEQ(last_seq, stream.max_live_seq))
	stream.loss_type = POSSIBLE_LOSS;
    else
	stream.loss_type = LOSS;
    stream.loss_time = k->rexmit_pkt->timestamp;
    stream.loss_seq = seq;
    stream.loss_end_time = k->timestamp;
    stream.loss_last_seq = stream.max_live_seq;

    // We just completed a loss event, so reset max_live_seq and max_loss_seq.
    stream.max_live_seq = last_seq;
    if (SEQ_GT(stream.max_seq, stream.max_loss_seq))
	stream.max_loss_seq = stream.max_seq;
}

void
CalculateFlows::LossInfo::post_update_state(const Packet *p, Pkt *k, CalculateFlows *cf)
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
	
	// find acked packet
	if (Pkt *acked_pkt = ack_stream.find_acked_pkt(ack, k->timestamp)) {
	    acked_pkt->nacks++;
	    struct timeval bounce = k->timestamp - acked_pkt->timestamp;
	    if (!ack_stream.have_ack_bounce || bounce < ack_stream.min_ack_bounce) {
		ack_stream.have_ack_bounce = true;
		ack_stream.min_ack_bounce = bounce;
	    }
	    // check whether this acknowledges something in the last loss
	    // event; if so, we should output the loss event
	    if (ack_stream.loss_type != NO_LOSS
		&& SEQ_GT(ack, ack_stream.loss_seq)) {
		// check for a false loss event: we don't believe the ack
		// could have seen the retransmitted packet yet
		if (k->timestamp - ack_stream.loss_end_time < ack_stream.min_ack_bounce)
		    ack_stream.loss_type = FALSE_LOSS;
		ack_stream.output_loss(_aggregate, !direction, cf);
	    }
	}
    }
}

void
CalculateFlows::LossInfo::handle_packet(const Packet *p, CalculateFlows *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // update timestamp and sequence number offsets at beginning of connection
    Pkt *k = pre_update_state(p, parent);

    int direction = (PAINT_ANNO(p) & 1);
    
    if (k->last_seq != k->seq) {
	calculate_loss_events2(k, direction, parent); //calculate loss if any
	// XXX calculate_loss(seq, seqlen, direction); //calculate loss if any
    }

    // update counters, maximum sequence numbers, and so forth
    post_update_state(p, k, parent);
}


// CALCULATEFLOWS PROPER

CalculateFlows::CalculateFlows()
    : Element(1, 1), _tipfd(0), _loss_file(0), _stat_file(0), _free_pkt(0)
{
    MOD_INC_USE_COUNT;
}

CalculateFlows::~CalculateFlows()
{
    MOD_DEC_USE_COUNT;
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
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
		    cpKeywords,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "FLOWDUMPS", cpElement,  "ToIPFlowDumps element pointer (notifier)", &tipfd_element,
		    "LOSSFILE", cpFilename, "filename for loss info", &_loss_filename,
		    "STATFILE", cpFilename, "filename for loss statistics", &_stat_filename,
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
CalculateFlows::initialize(ErrorHandler *errh)
{
    if (!_loss_filename)
	/* nada */;
    else if (_loss_filename == "-")
	_loss_file = stdout;
    else if (!(_loss_file = fopen(_loss_filename.cc(), "w")))
	return errh->error("%s: %s", _loss_filename.cc(), strerror(errno));
    if (_loss_file)
	fprintf(_loss_file, "# losstype aggregate direction time seq end_time end_seq\n");
    
    if (!_stat_filename)
	/* nada */;
    else if (_stat_filename == "-")
	_stat_file = stdout;
    else if (!(_stat_file = fopen(_stat_filename.cc(), "w")))
	return errh->error("%s: %s", _stat_filename.cc(), strerror(errno));
    if (_stat_file)
	fprintf(_stat_file, "#agg d\ttot_pkt\ttot_seq\tloss_e\tploss_e\tfloss_e\n");    
    return 0;
}

void
CalculateFlows::cleanup(CleanupStage)
{
    for (MapLoss::Iterator iter = _loss_map.first(); iter; iter++) {
	LossInfo *losstmp = const_cast<LossInfo *>(iter.value());
	losstmp->kill(this);
    }
    _loss_map.clear();
    if (_loss_file)
	fclose(_loss_file);
    if (_stat_file)
	fclose(_stat_file);
}

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
	      if ((loss = new LossInfo(p)))
		  _loss_map.insert(aggregate, loss);
	      else {
		  click_chatter("out of memory!");
		  p->kill();
		  return 0;
	      }
	  }
	  loss->handle_packet(p, this);
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
	    tmploss->kill(this);
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

#if 0
void
CalculateFlows::LossInfo::calculate_loss(tcp_seq_t seq, uint32_t seqlen, unsigned paint)
{
    assert(paint < 2);
    StreamInfo &stream = _stream[paint];
    
    if (SEQ_LT(stream.max_seq + 1, seq) && stream.total_packets) {
	printf("Possible gap in Byte Sequence flow %u:%u %u - %u\n", _aggregate, paint, stream.max_seq, seq);
    }

    // XXX this code is broken
    if (SEQ_LT(seq + 1, stream.max_seq) && !_out_of_order) {  // we do a retransmission  (Bytes are lost...)
	if (SEQ_LT(seq + seqlen, stream.max_seq)) { // are we transmiting totally new bytes also?
	    stream.lost_seq += seqlen;
	} else { // we retransmit something old but partial
	    stream.lost_seq += stream.max_seq - seq;
	}
	stream.lost_packets++;
    }
}
#endif

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)

#include <click/bighashmap.cc>
