// -*- mode: c++; c-basic-offset: 4 -*-
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
CLICK_DECLS

CalculateFlows::StreamInfo::StreamInfo()
    : have_init_seq(false), have_syn(false), have_fin(false),
      have_ack_bounce(false),
      init_seq(0), max_seq(0), max_ack(0), max_live_seq(0), max_loss_seq(0),
      total_packets(0), total_seq(0),
      loss_events(0), possible_loss_events(0), false_loss_events(0),
      event_id(0),
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
	    if (k->ip_id && k->ip_id == x->ip_id)
		// network duplicate
		k->type = Pkt::DUPLICATE;
	    else
		// retransmission
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
CalculateFlows::StreamInfo::output_loss(LossInfo *loss_info, unsigned direction, CalculateFlows *cf)
{
    assert(direction < 2);
    if (loss_type != NO_LOSS) {
	// figure out loss type, make accounting
	uint32_t aggregate = loss_info->aggregate();
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

	// output to ToIPFlowDumps
	if (ToIPFlowDumps *flowd = cf->flow_dumps()) {
	    StringAccum sa;
	    sa << loss_type_str << direction_str;
	    if (!flowd->absolute_time() && !flowd->absolute_seq())
		// common case
		sa << loss_time << ' ' << loss_seq << ' '
		   << loss_end_time << ' ' << loss_last_seq;
	    else {
		struct timeval time_adj = (flowd->absolute_time() ? loss_info->init_time() : make_timeval(0, 0));
		uint32_t seq_adj = (flowd->absolute_seq() ? init_seq : 0);
		sa << (loss_time + time_adj) << ' '
		   << (loss_seq + seq_adj) << ' '
		   << (loss_end_time + time_adj) << ' '
		   << (loss_last_seq + seq_adj);
	    }
	    sa << ' ' << '0'; // XXX nacks
	    cf->flow_dumps()->add_note(aggregate, sa.take_string());
	}

	// output to loss file
	if (cf->loss_file()) {
	    if (cf->absolute_time())
		loss_time += loss_info->init_time(), loss_end_time += loss_info->init_time();
	    if (cf->absolute_seq())
		loss_seq += init_seq, loss_last_seq += init_seq;
	    fprintf(cf->loss_file(), "%s %u%s%ld.%06ld %u %ld.%06ld %u\n",
		    loss_type_str, aggregate, direction_str,
		    loss_time.tv_sec, loss_time.tv_usec, loss_seq,
		    loss_end_time.tv_sec, loss_end_time.tv_usec, loss_last_seq);
	}

	// clear loss
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
    _stream[0].output_loss(this, 0, cf);
    _stream[1].output_loss(this, 1, cf);
    cf->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    cf->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    if (cf->stat_file()) {
	fprintf(cf->stat_file(), "%u >\t%u\t%u\t%u\t%u\t%u\n",
		_aggregate, _stream[0].total_packets, _stream[0].total_seq,
		_stream[0].loss_events, _stream[0].possible_loss_events,
		_stream[0].false_loss_events);
	fprintf(cf->stat_file(), "%u <\t%u\t%u\t%u\t%u\t%u\n",
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
    
    // set TCP sequence number offsets on first Pkt
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
	    (parent->_ip_id ? iph->ip_id : 0),
	    p->timestamp_anno() - _init_time, stream.event_id);
    stream.insert(k);
    
    // save everything else for later
    return k;
}


void
CalculateFlows::LossInfo::calculate_loss_events(Pkt *k, unsigned direction, CalculateFlows *parent)
{
    assert(direction < 2);
    StreamInfo &stream = _stream[direction];
    tcp_seq_t seq = k->seq;
    tcp_seq_t last_seq = k->last_seq;

    // Return if this is new or out-of-order data
    if (SEQ_GEQ(seq, stream.max_seq) || k->type == Pkt::ALL_NEW
	|| k->type == Pkt::REORDERED || k->type == Pkt::DUPLICATE)
	return;
    
    // Return if this retransmission is due to a previous loss event
    assert(k->rexmit_pkt);
    if (k->event_id != k->rexmit_pkt->event_id)
	return;

    // Return if this is a keepalive (XXX)
    if (stream.max_seq == k->last_seq && k->last_seq == k->seq + 1)
	return;
    
    // If we get this far, it is a new loss event.
    
    // Update the event ID
    stream.event_id++;
    k->event_id = stream.event_id;

    // Store information about the loss event
    if (stream.loss_type != NO_LOSS) // output any previous loss event
	stream.output_loss(this, direction, parent);
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
	    click_chatter("%u: different SYN seqnos!", _aggregate); // XXX report error
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

	    // output ack match
	    if (cf->ack_match()) {
		StringAccum sa;
		sa << "ackm " << (direction ? '>' : '<') << ' '
		   << k->timestamp << ' ' << ack << ' '
		   << acked_pkt->timestamp << ' ' << acked_pkt->last_seq;
		cf->flow_dumps()->add_note(_aggregate, sa.take_string());
	    }
	    
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
		if (k->timestamp - ack_stream.loss_end_time < 0.6 * ack_stream.min_ack_bounce
		    && ack_stream.have_ack_bounce)
		    ack_stream.loss_type = FALSE_LOSS;
		ack_stream.output_loss(this, !direction, cf);
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
	calculate_loss_events(k, direction, parent); //calculate loss if any
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
    bool absolute_time = false, absolute_seq = false, ack_match = false, ip_id = true;
    if (cp_va_parse(conf, this, errh,
		    cpKeywords,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "FLOWDUMPS", cpElement,  "ToIPFlowDumps element pointer (notifier)", &tipfd_element,
		    "LOSSFILE", cpFilename, "filename for loss info", &_loss_filename,
		    "STATFILE", cpFilename, "filename for loss statistics", &_stat_filename,
		    "ABSOLUTE_TIME", cpBool, "output absolute timestamps?", &absolute_time,
		    "ABSOLUTE_SEQ", cpBool, "output absolute sequence numbers?", &absolute_seq,
		    "ACK_MATCH", cpBool, "output ack matches?", &ack_match,
		    "IP_ID", cpBool, "use IP ID to distinguish duplicates?", &ip_id,
		    0) < 0)
        return -1;
    
    AggregateIPFlows *af = 0;
    if (af_element && !(af = (AggregateIPFlows *)(af_element->cast("AggregateIPFlows"))))
	return errh->error("first element not an AggregateIPFlows");
    else if (af)
	af->add_listener(this);
    
    if (!tipfd_element || !(_tipfd = (ToIPFlowDumps *)(tipfd_element->cast("ToIPFlowDumps"))))
	return errh->error("first element not an ToIPFlowDumps");

    _absolute_time = absolute_time;
    _absolute_seq = absolute_seq;
    _ack_match = (ack_match && _tipfd);
    _ip_id = ip_id;
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
    for (MapLoss::iterator iter = _loss_map.begin(); iter; iter++) {
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
    uint32_t aggregate = AGGREGATE_ANNO(p);
    if (aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP) {
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
	return p;
    } else {
	checked_output_push(1, p);
	return 0;
    }
}

void 
CalculateFlows::aggregate_notify(uint32_t aggregate, AggregateEvent event, const Packet *)
{
    if (event == DELETE_AGG)
	if (LossInfo *tmploss = _loss_map.find(aggregate)) {
	    _loss_map.remove(aggregate);
	    tmploss->kill(this);
	}
}


ELEMENT_REQUIRES(userlevel ToIPFlowDumps AggregateNotifier)
EXPORT_ELEMENT(CalculateFlows)
#include <click/bighashmap.cc>
CLICK_ENDDECLS
