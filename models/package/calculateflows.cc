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
CalculateFlows::StreamInfo::output_loss(uint32_t aggregate, unsigned direction, ToIPFlowDumps *td)
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
	StringAccum sa;
	sa << loss_type_str << direction_str << loss_time
	   << ' ' << loss_seq << ' ' << loss_end_time
	   << ' ' << loss_last_seq << ' ' << '0'; // XXX nacks
	printf("# %u %s\n", aggregate, sa.cc());
	td->add_note(aggregate, sa.take_string());
	loss_type = NO_LOSS;
    }
}


// LOSSINFO

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
CalculateFlows::LossInfo::kill(CalculateFlows *f)
{
    _stream[0].output_loss(_aggregate, 0, f->tipfd());
    _stream[1].output_loss(_aggregate, 1, f->tipfd());
    f->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    f->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    if (_eventfiles)
	print_stats();
    delete this;
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
CalculateFlows::LossInfo::calculate_loss_events2(Pkt *k, unsigned direction, ToIPFlowDumps *tipfd)
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
    if (stream.loss_type != NO_LOSS)
	stream.output_loss(_aggregate, direction, tipfd);
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
		ack_stream.output_loss(_aggregate, !direction, cf->tipfd());
	    }
	}
    }
}

void
CalculateFlows::LossInfo::handle_packet(const Packet *p, CalculateFlows *parent, ToIPFlowDumps *flowdumps)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // update timestamp and sequence number offsets at beginning of connection
    Pkt *k = pre_update_state(p, parent);

    int direction = (PAINT_ANNO(p) & 1);
    
    if (k->last_seq != k->seq) {
	calculate_loss_events2(k, direction, flowdumps); //calculate loss if any
	// XXX calculate_loss(seq, seqlen, direction); //calculate loss if any
    }

    // update counters, maximum sequence numbers, and so forth
    post_update_state(p, k, parent);
}


// CALCULATEFLOWS PROPER

CalculateFlows::CalculateFlows()
    : Element(1, 1), _tipfd(0), _free_pkt(0)
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
	      if ((loss = new LossInfo(p, true, _outfilename)))
		  _loss_map.insert(aggregate, loss);
	      else {
		  click_chatter("out of memory!");
		  p->kill();
		  return 0;
	      }
	  }
	  loss->handle_packet(p, this, _tipfd);
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
