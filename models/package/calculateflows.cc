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
CalculateFlows::StreamInfo::categorize(Pkt *np, ConnInfo *conn, CalculateFlows *parent)
{
    assert(np->flags == 0);

    // check that timestamp makes sense
    if (np->prev && np->timestamp < np->prev->timestamp) {
	click_chatter("timestamp confusion");
	np->timestamp = np->prev->timestamp;
    }

    // exit if this is a pure ack
    if (np->seq == np->last_seq)
	// NB pure acks will not include IP ID check for network duplicates
	return;
    
    // exit if there is any new data
    if (SEQ_GT(np->last_seq, max_seq)) {
	np->flags |= Pkt::F_NEW;
	if (SEQ_LT(np->seq, max_seq))
	    np->flags |= Pkt::F_REXMIT;
	return;
    }

    // Otherwise, it is a reordering, or possibly a retransmission.
    // Find the most recent retransmission of overlapping data.
    Pkt *x = np->prev;
    while (x) {
	if (np->seq == x->seq) {
	    np->flags |= Pkt::F_REXMIT;
	    if (np->ip_id && np->ip_id == x->ip_id
		&& np->last_seq == x->last_seq)
		// network duplicate
		np->flags |= Pkt::F_DUPLICATE;
	    else if (np->last_seq == max_seq && np->seq + 1 == np->last_seq)
		// keepalive XXX
		np->flags |= Pkt::F_KEEPALIVE;
	    else if (np->event_id != x->event_id)
		// retransmission of something from an old loss event
		/* nada */;
	    else
		// new loss event
		register_loss_event(x, np, conn, parent);
	    return;
	} else if (x->flags == Pkt::F_NEW && SEQ_LEQ(x->last_seq, np->seq)) {
	    // reordering
	    np->flags |= Pkt::F_REORDER;
	    return;
	} else if ((SEQ_LEQ(x->seq, np->seq) && SEQ_LT(np->seq, x->last_seq))
		   || (SEQ_LT(x->seq, np->last_seq) && SEQ_LEQ(np->last_seq, x->last_seq))) {
	    // odd partial retransmission
	    np->flags |= Pkt::F_REXMIT | Pkt::F_STRANGE;
	    return;
	} else
	    x = x->prev;
    }
    
    // If we ran out of packets, it's a reordering.
    np->flags |= Pkt::F_REORDER;
}

void
CalculateFlows::StreamInfo::register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *conn, CalculateFlows *parent)
{
    // Update the event ID
    event_id++;
    endk->event_id = event_id;

    // Store information about the loss event
    if (loss_type != NO_LOSS) // output any previous loss event
	output_loss(conn, parent);
    if (SEQ_GT(max_ack, endk->seq))
	loss_type = FALSE_LOSS;
    else if (SEQ_GEQ(endk->last_seq, max_live_seq))
	loss_type = POSSIBLE_LOSS;
    else
	loss_type = LOSS;
    loss_time = startk->timestamp;
    loss_seq = startk->seq;
    loss_end_time = endk->timestamp;
    loss_last_seq = max_live_seq;

    // We just completed a loss event, so reset max_live_seq and max_loss_seq.
    max_live_seq = endk->last_seq;
    if (SEQ_GT(max_seq, max_loss_seq))
	max_loss_seq = max_seq;
}

void
CalculateFlows::StreamInfo::update_counters(const Pkt *np, const click_tcp *tcph)
{
    // update counters
    total_packets++;
    total_seq += np->last_seq - np->seq;
    
    // mark SYN and FIN packets
    if (tcph->th_flags & TH_SYN) {
	if (have_syn && syn_seq != np->seq)
	    click_chatter("different SYN seqnos!"); // XXX report error
	else {
	    syn_seq = np->seq;
	    have_syn = true;
	}
    }
    if (tcph->th_flags & TH_FIN) {
	if (have_fin && fin_seq != np->last_seq - 1)
	    click_chatter("different FIN seqnos!"); // XXX report error
	else {
	    fin_seq = np->last_seq - 1;
	    have_fin = true;
	}
    }

    // update max_seq and max_live_seq
    if (SEQ_GT(np->last_seq, max_seq))
	max_seq = np->last_seq;
    if (SEQ_GT(np->last_seq, max_live_seq))
	max_live_seq = np->last_seq;    
}

CalculateFlows::Pkt *
CalculateFlows::StreamInfo::find_acked_pkt(tcp_seq_t ack, const struct timeval &timestamp)
{
    // XXX start from the middle?
    Pkt *potential_answer = 0;
    for (Pkt *k = pkt_tail; k; k = k->prev) {
	if (k->last_seq == ack) {
	    if ((k->flags & Pkt::F_REXMIT)
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
CalculateFlows::StreamInfo::output_loss(ConnInfo *loss_info, CalculateFlows *cf)
{
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
	    flowd->add_note(aggregate, sa.take_string());
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

CalculateFlows::ConnInfo::ConnInfo(const Packet *p)
    : _aggregate(AGGREGATE_ANNO(p))
{
    assert(_aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header())
	   && p->transport_length() >= (int)sizeof(click_udp));
    _flowid = IPFlowID(p);
    
    // set initial timestamp
    if (timerisset(&p->timestamp_anno()))
	_init_time = p->timestamp_anno() - make_timeval(0, 1);
    else
	timerclear(&_init_time);

    // initialize streams
    _stream[0].direction = 0;
    _stream[1].direction = 1;
}

void
CalculateFlows::ConnInfo::kill(CalculateFlows *cf)
{
    _stream[0].output_loss(this, cf);
    _stream[1].output_loss(this, cf);
    if (cf->stat_file()) {
	timeval end_time = (_stream[0].pkt_tail ? _stream[0].pkt_tail->timestamp : _init_time);
	if (_stream[1].pkt_tail && _stream[1].pkt_tail->timestamp > end_time)
	    end_time = _stream[1].pkt_tail->timestamp;

	fprintf(cf->stat_file(), "<connection aggregate='%u' src='%s' sport='%d' dst='%s' dport='%d' begin='%ld.%06ld' duration='%ld.%06ld'>\n\
  <flow dir='0' loss='%u' ploss='%u' floss='%u' />\n\
  <flow dir='1' loss='%u' ploss='%u' floss='%u' />\n\
</connection>\n",
		_aggregate, _flowid.saddr().s().cc(), ntohs(_flowid.sport()),
		_flowid.daddr().s().cc(), ntohs(_flowid.dport()),
		_init_time.tv_sec, _init_time.tv_usec,
		end_time.tv_sec, end_time.tv_usec,
		_stream[0].loss_events, _stream[0].possible_loss_events,
		_stream[0].false_loss_events,
		_stream[1].loss_events, _stream[1].possible_loss_events,
		_stream[1].false_loss_events);
    }
    cf->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    cf->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    delete this;
}

CalculateFlows::Pkt *
CalculateFlows::ConnInfo::create_pkt(const Packet *p, CalculateFlows *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header())
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
    if (Pkt *np = parent->new_pkt()) {
	const click_ip *iph = p->ip_header();

	// set fields appropriately
	np->seq = ntohl(tcph->th_seq) - stream.init_seq;
	np->last_seq = np->seq + calculate_seqlen(iph, tcph);
	np->ack = ntohl(tcph->th_ack) - ack_stream.init_seq;
	np->ip_id = (parent->_ip_id ? iph->ip_id : 0);
	np->timestamp = p->timestamp_anno() - _init_time;
	np->flags = 0;
	np->event_id = stream.event_id;

	// hook up to packet list
	np->next = 0;
	np->prev = stream.pkt_tail;
	if (stream.pkt_tail)
	    stream.pkt_tail = stream.pkt_tail->next = np;
	else
	    stream.pkt_head = stream.pkt_tail = np;

	return np;
    } else
	return 0;
}

void
CalculateFlows::ConnInfo::post_update_state(const Packet *p, Pkt *k, CalculateFlows *cf)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);

    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);

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
		ack_stream.output_loss(this, cf);
	    }
	}
    }
}

void
CalculateFlows::ConnInfo::handle_packet(const Packet *p, CalculateFlows *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // update timestamp and sequence number offsets at beginning of connection
    if (Pkt *k = create_pkt(p, parent)) {
	int direction = (PAINT_ANNO(p) & 1);
	_stream[direction].categorize(k, this, parent);
	_stream[direction].update_counters(k, p->tcp_header());

	// update counters, maximum sequence numbers, and so forth
	post_update_state(p, k, parent);
    }
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
    _tipfd = 0;
    bool absolute_time = false, absolute_seq = false, ack_match = false, ip_id = true;
    if (cp_va_parse(conf, this, errh,
		    cpKeywords,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "FLOWDUMPS", cpElement,  "ToIPFlowDumps element pointer (notifier)", &tipfd_element,
		    "LOSSFILE", cpFilename, "filename for loss info", &_loss_filename,
		    "STATFILE", cpFilename, "filename for XML loss statistics", &_stat_filename,
		    "ABSOLUTE_TIME", cpBool, "output absolute timestamps?", &absolute_time,
		    "ABSOLUTE_SEQ", cpBool, "output absolute sequence numbers?", &absolute_seq,
		    "ACK_MATCH", cpBool, "output ack matches?", &ack_match,
		    "IP_ID", cpBool, "use IP ID to distinguish duplicates?", &ip_id,
		    0) < 0)
        return -1;
    
    AggregateIPFlows *af = 0;
    if (af_element && !(af = (AggregateIPFlows *)(af_element->cast("AggregateIPFlows"))))
	return errh->error("NOTIFIER must be an AggregateIPFlows element");
    else if (af)
	af->add_listener(this);
    
    if (tipfd_element && !(_tipfd = (ToIPFlowDumps *)(tipfd_element->cast("ToIPFlowDumps"))))
	return errh->error("FLOWDUMPS must be a ToIPFlowDumps element");

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
    if (_stat_file) {
	fprintf(_stat_file, "<?xml version='1.0' standalone='yes'?>\n\
<connections");
	if (_tipfd)
	    fprintf(_stat_file, " filepattern='%s'",
		    _tipfd->output_pattern().cc());
	fprintf(_stat_file, ">\n");
    }

    return 0;
}

void
CalculateFlows::cleanup(CleanupStage)
{
    for (ConnMap::iterator iter = _conn_map.begin(); iter; iter++) {
	ConnInfo *losstmp = const_cast<ConnInfo *>(iter.value());
	losstmp->kill(this);
    }
    _conn_map.clear();
    if (_loss_file)
	fclose(_loss_file);
    if (_stat_file) {
	fprintf(_stat_file, "</connections>\n");
	fclose(_stat_file);
    }
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
	ConnInfo *loss = _conn_map.find(aggregate);
	if (!loss) {
	    if ((loss = new ConnInfo(p)))
		_conn_map.insert(aggregate, loss);
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
	if (ConnInfo *tmploss = _conn_map.find(aggregate)) {
	    _conn_map.remove(aggregate);
	    tmploss->kill(this);
	}
}


enum { H_CLEAR };

int
CalculateFlows::write_handler(const String &, Element *e, void *thunk, ErrorHandler *)
{
    CalculateFlows *cf = static_cast<CalculateFlows *>(e);
    switch ((intptr_t)thunk) {
      case H_CLEAR:
	for (ConnMap::iterator i = cf->_conn_map.begin(); i; i++)
	    i.value()->kill(cf);
	cf->_conn_map.clear();
	return 0;
      default:
	return -1;
    }
}

void
CalculateFlows::add_handlers()
{
    add_write_handler("clear", write_handler, (void *)H_CLEAR);
}


ELEMENT_REQUIRES(userlevel ToIPFlowDumps AggregateNotifier)
EXPORT_ELEMENT(CalculateFlows)
#include <click/bighashmap.cc>
CLICK_ENDDECLS
