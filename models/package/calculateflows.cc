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
#include "elements/analysis/aggregateipflows.hh"
#include "elements/analysis/toipsumdump.hh"
CLICK_DECLS

static inline struct timeval
operator*(double frac, const struct timeval &tv)
{
    double what = frac * (tv.tv_sec + tv.tv_usec / 1e6);
    int32_t sec = (int32_t)what;
    return make_timeval(sec, (int32_t)((what - sec) * 1e6));
}

CalculateFlows::StreamInfo::StreamInfo()
    : have_init_seq(false), have_syn(false), have_fin(false),
      have_ack_latency(false), filled_rcv_window(false),
      init_seq(0), max_seq(0), max_ack(0), max_live_seq(0), max_loss_seq(0),
      total_packets(0), total_seq(0),
      loss_events(0), possible_loss_events(0), false_loss_events(0),
      event_id(0),
      end_rcv_window(0), rcv_window_scale(0),
      pkt_head(0), pkt_tail(0), pkt_data_tail(0),
      loss_trail(0)
{
    loss.type = NO_LOSS;
}

CalculateFlows::StreamInfo::~StreamInfo()
{
    while (LossBlock *b = loss_trail) {
	loss_trail = b->next;
	delete b;
    }
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
    if (np->seq == np->end_seq)
	// NB pure acks will not include IP ID check for network duplicates
	return;
    
    // exit if there is any new data
    if (SEQ_GT(np->end_seq, max_seq)) {
	np->flags |= Pkt::F_NEW;
	if (SEQ_LT(np->seq, max_seq))
	    np->flags |= Pkt::F_REXMIT;
	return;
    }

    // Otherwise, it is a reordering, or possibly a retransmission.
    // Find the most relevant previous transmission of overlapping data.
    Pkt *rexmit = 0;
    Pkt *x;
    for (x = np->prev; x; x = x->prev) {
	
	if ((x->flags & Pkt::F_NEW)
	    && SEQ_LEQ(x->end_seq, np->seq)) {
	    // packet has new data older than our oldest data;
	    // therefore, nothing relevant can precede it.
	    // either we have a retransmission or a reordering.
	    break;

	} else if (np->seq == np->end_seq) {
	    // ignore pure acks
	
	} else if (np->seq == x->seq) {
	    // this packet overlaps with our data
	    np->flags |= Pkt::F_REXMIT;
	    
	    if (np->ip_id
		&& np->ip_id == x->ip_id
		&& np->end_seq == x->end_seq) {
		// network duplicate
		np->flags |= Pkt::F_DUPLICATE;
		return;
	    } else if (np->end_seq == max_seq
		       && np->seq + 1 == np->end_seq) {
		// keepalive XXX
		np->flags |= Pkt::F_KEEPALIVE;
		return;
	    }

	    if (np->end_seq == x->end_seq) {
		// it has the same data as we do; call off the search
		np->flags |= Pkt::F_FULL_REXMIT;
		rexmit = x;
		break;
	    }
	    if (!rexmit)
		rexmit = x;
	    
	} else if ((SEQ_LEQ(x->seq, np->seq) && SEQ_LT(np->seq, x->end_seq))
		   || (SEQ_LT(x->seq, np->end_seq) && SEQ_LEQ(np->end_seq, x->end_seq))) {
	    // partial retransmission. There might be a more relevant
	    // preceding retransmission, so keep searching for one.
	    np->flags |= Pkt::F_REXMIT;
	    rexmit = x;
	}
    }
    
    // we have identified retransmissions already.
    if (np->flags & Pkt::F_REXMIT) {
	// ignore retransmission of something from an old loss event
	if (rexmit->event_id == np->event_id)
	    // new loss event
	    register_loss_event(rexmit, np, conn, parent);
    } else {
	// if not a retransmission, then a reordering
	np->flags |= Pkt::F_REORDER;
	// mark intervening packets as in a reordering event
	for (x = (x ? x->next : pkt_head); x; x = x->next)
	    x->flags |= Pkt::F_IN_REORDER;
    }
}

void
CalculateFlows::StreamInfo::register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *conn, CalculateFlows *parent)
{
    // Update the event ID
    event_id++;
    endk->event_id = event_id;

    // Store information about the loss event
    if (loss.type != NO_LOSS) // output any previous loss event
	output_loss(conn, parent);
    if (SEQ_GT(max_ack, endk->seq))
	loss.type = FALSE_LOSS;
    else if (SEQ_GEQ(endk->end_seq, max_live_seq))
	loss.type = POSSIBLE_LOSS;
    else
	loss.type = LOSS;
    loss.time = startk->timestamp;
    loss.seq = startk->seq;
    loss.end_time = endk->timestamp;
    loss.top_seq = max_live_seq;

    // We just completed a loss event, so reset max_live_seq and max_loss_seq.
    max_live_seq = endk->end_seq;
    if (SEQ_GT(max_seq, max_loss_seq))
	max_loss_seq = max_seq;
}

void
CalculateFlows::StreamInfo::update_counters(const Pkt *np, const click_tcp *tcph, int transport_length, const ConnInfo *conn)
{
    // update counters
    total_packets++;
    total_seq += np->end_seq - np->seq;
    
    // SYN processing
    if (tcph->th_flags & TH_SYN) {
	if (have_syn && syn_seq != np->seq)
	    click_chatter("%u: different SYN seqnos!", conn->aggregate()); // XXX report error
	else {
	    syn_seq = np->seq;
	    have_syn = true;

	    // look for window scaling option
	    if (tcph->th_off > 5) {
		const uint8_t *oa = reinterpret_cast<const uint8_t *>(tcph);
		int hlen = ((int)(tcph->th_off << 2) < transport_length ? tcph->th_off << 2 : transport_length);
		for (int oi = 20; oi < hlen; ) {
		    if (oa[oi] == TCPOPT_NOP) {
			oi++;
			continue;
		    } else if (oa[oi] == TCPOPT_EOL)
			break;

		    int xlen = oa[oi+1];
		    if (xlen < 2 || oi + xlen > hlen) // bad option
			break;

		    if (oa[oi] == TCPOPT_WSCALE && xlen == TCPOLEN_WSCALE)
			rcv_window_scale = (oa[oi+2] <= 14 ? oa[oi+2] : 14);

		    oi += xlen;
		}
	    }
	}
    }

    // FIN processing
    if (tcph->th_flags & TH_FIN) {
	if (have_fin && fin_seq != np->end_seq - 1)
	    click_chatter("%u: different FIN seqnos!", conn->aggregate()); // XXX report error
	else {
	    fin_seq = np->end_seq - 1;
	    have_fin = true;
	}
    }

    // update max_seq and max_live_seq
    if (SEQ_GT(np->end_seq, max_seq))
	max_seq = np->end_seq;
    if (SEQ_GT(np->end_seq, max_live_seq))
	max_live_seq = np->end_seq;

    // update end_rcv_window
    end_rcv_window = np->ack + (ntohs(tcph->th_win) << rcv_window_scale);
}

CalculateFlows::Pkt *
CalculateFlows::StreamInfo::find_acked_pkt(tcp_seq_t ack, const struct timeval &timestamp, Pkt *search_hint) const
{
    // region of interest is:
    // bounded on the left by a packet whose end_seq < ack, and which is
    // neither a reordering nor a retransmission
    // bounded on the right by a packet whose seq >= ack, and which is not
    // part of a reordered block
    
    // move search_hint forward to right edge
    while (search_hint && !(SEQ_GEQ(search_hint->seq, ack)
			    && !(search_hint->flags & Pkt::F_IN_REORDER)))
	search_hint = search_hint->next;

    // move backwards to left edge
    Pkt *possible = 0;
    int possible_goodness = -1;
    for (Pkt *k = (search_hint ? search_hint->prev : pkt_data_tail);
	 k && (SEQ_GEQ(k->end_seq, ack)
	       || (k->flags & (Pkt::F_REORDER | Pkt::F_REXMIT)));
	 k = k->prev) {

	// a packet with end_seq == ack is definitely the right answer
	// if it is the first transmission of the relevant data
	// and there was no later retransmission
	if (possible_goodness <= 0
	    && k->end_seq == ack
	    && (k->flags & Pkt::F_NEW))
	    return k;

	// skip it if couldn't be an ack
	if (SEQ_LT(k->end_seq, ack) || SEQ_GEQ(k->seq, ack))
	    continue;

	// measure goodness == (ack latency fits) + (end_seq == ack)
	int goodness =
	    (!have_ack_latency || timestamp - k->timestamp >= min_ack_latency)
	    + (k->end_seq == ack);
	// store the best guess so far
	if (goodness > possible_goodness)
	    possible = k, possible_goodness = goodness;
    }

    return possible;
}

bool
CalculateFlows::LossInfo::unparse(StringAccum &sa, const StreamInfo *cstr, const ConnInfo *conn, bool include_aggregate, bool absolute_time, bool absolute_seq) const
{
    if (type == NO_LOSS)
	return false;

    // figure out loss type, count loss
    if (type == LOSS)
	sa << "loss ";
    else if (type == POSSIBLE_LOSS)
	sa << "ploss ";
    else
	sa << "floss ";

    // add (optional) aggregate number and direction
    if (include_aggregate)
	sa << conn->aggregate() << ' ';
    sa << (cstr->direction ? "< " : "> ");

    // add times and sequence numbers
    if (!absolute_time && !absolute_seq)
	// common case
	sa << time << ' ' << seq << ' '
	   << end_time << ' ' << top_seq;
    else {
	if (absolute_time)
	    sa << (time + conn->init_time()) << ' ';
	else
	    sa << time << ' ';
	if (absolute_seq)
	    sa << (seq + cstr->init_seq) << ' ';
	else
	    sa << seq << ' ';
	if (absolute_time)
	    sa << (end_time + conn->init_time()) << ' ';
	else
	    sa << end_time << ' ';
	if (absolute_seq)
	    sa << (top_seq + cstr->init_seq);
	else
	    sa << top_seq;
    }

    return true;
}

void
CalculateFlows::StreamInfo::output_loss(ConnInfo *conn, CalculateFlows *cf)
{
    if (loss.type == NO_LOSS)
	return;

    // figure out loss type, count loss
    if (loss.type == LOSS)
	loss_events++;
    else if (loss.type == POSSIBLE_LOSS)
	possible_loss_events++;
    else {
	assert(loss.type == FALSE_LOSS);
	false_loss_events++;
    }

    // output to ToIPSummaryDump and/or ToIPFlowDumps
    if (ToIPFlowDumps *flowd = cf->flow_dumps()) {
	StringAccum sa(80);
	loss.unparse(sa, this, conn, false, flowd->absolute_time(), flowd->absolute_seq());
	flowd->add_note(conn->aggregate(), sa.take_string());
    }
    if (ToIPSummaryDump *sumd = cf->summary_dump()) {
	StringAccum sa(80);
	sa << 'a';
	loss.unparse(sa, this, conn, true);
	sumd->add_note(sa.take_string());
    }

    // store loss
    if (!loss_trail || loss_trail->n == LossBlock::CAPACITY)
	loss_trail = new LossBlock(loss_trail);
    loss_trail->loss[loss_trail->n++] = loss;
    
    // clear loss
    loss.type = NO_LOSS;
}


// LOSSINFO

CalculateFlows::ConnInfo::ConnInfo(const Packet *p, const HandlerCall *filepos_call)
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

    // set file position
    if (filepos_call)
	_filepos = filepos_call->call_read().trim_space();

    // initialize streams
    _stream[0].direction = 0;
    _stream[1].direction = 1;
}

void
CalculateFlows::LossInfo::unparse_xml(StringAccum &sa) const
{
    if (type == NO_LOSS)
	return;

    // figure out loss type, count loss
    sa << "    <anno type='";
    if (type == LOSS)
	sa << "loss' ";
    else if (type == POSSIBLE_LOSS)
	sa << "ploss' ";
    else
	sa << "floss' ";

    // add times and sequence numbers; all are relative in XML
    sa << "time='" << time << "' seq='" << seq << "' endtime='"
       << end_time << "' lastseq='" << top_seq << "' />\n";
}

void
CalculateFlows::LossBlock::write_xml(FILE *f) const
{
    if (next)
	next->write_xml(f);
    StringAccum sa(n * 80);
    for (int i = 0; i < n; i++)
	loss[i].unparse_xml(sa);
    fwrite(sa.data(), 1, sa.length(), f);
}

void
CalculateFlows::StreamInfo::write_ack_latency_xml(ConnInfo *conn, FILE *f) const
{
    fprintf(f, "    <acklatency");
    if (have_ack_latency)
	fprintf(f, " min='%ld.%06ld'", min_ack_latency.tv_sec, min_ack_latency.tv_usec);
    fprintf(f, ">\n");
    
    const StreamInfo *acks = conn->stream(!direction);
    Pkt *hint = pkt_head;
    tcp_seq_t last_ack = (tcp_seq_t) -1;
    for (Pkt *ack = acks->pkt_head; ack; ack = ack->next)
	if (ack->ack != last_ack) {
	    last_ack = ack->ack;
	    if (Pkt *k = find_acked_pkt(ack->ack, ack->timestamp, hint)) {
		struct timeval latency = ack->timestamp - k->timestamp;
		fprintf(f, "%ld.%06ld %u %ld.%06ld\n", k->timestamp.tv_sec, k->timestamp.tv_usec, k->end_seq, latency.tv_sec, latency.tv_usec);
		hint = k;
	    }
	}
    
    fprintf(f, "    </acklatency>\n");
}

void
CalculateFlows::StreamInfo::write_full_rcv_window_xml(FILE *f) const
{
    if (filled_rcv_window) {
	fprintf(f, "    <fullrcvwindow>\n");
	for (Pkt *k = pkt_head; k; k = k->next)
	    if (k->flags & Pkt::F_FILLS_RCV_WINDOW)
		fprintf(f, "%ld.%06ld %u\n", k->timestamp.tv_sec, k->timestamp.tv_usec, k->end_seq);
	fprintf(f, "    </fullrcvwindow>\n");
    }
}

void
CalculateFlows::StreamInfo::write_xml(ConnInfo *conn, FILE *f, bool ack_latency, bool full_rcv_window) const
{
    fprintf(f, "  <stream dir='%d' beginseq='%u' seqlen='%u' nloss='%u' nploss='%u' nfloss='%u'",
	    direction, init_seq, total_seq, loss_events, possible_loss_events, false_loss_events);
    if (have_ack_latency)
	fprintf(f, " minacklatency='%ld.%06ld'", min_ack_latency.tv_sec, min_ack_latency.tv_usec);
    if (loss_trail || (ack_latency && have_ack_latency)
	|| (full_rcv_window && filled_rcv_window)) {
	fprintf(f, ">\n");
	if (loss_trail)
	    loss_trail->write_xml(f);
	if (ack_latency)
	    write_ack_latency_xml(conn, f);
	if (full_rcv_window)
	    write_full_rcv_window_xml(f);
	fprintf(f, "  </stream>\n");
    } else
	fprintf(f, " />\n");
}

void
CalculateFlows::ConnInfo::kill(CalculateFlows *cf)
{
    _stream[0].output_loss(this, cf);
    _stream[1].output_loss(this, cf);
    if (FILE *f = cf->traceinfo_file()) {
	timeval end_time = (_stream[0].pkt_tail ? _stream[0].pkt_tail->timestamp : _init_time);
	if (_stream[1].pkt_tail && _stream[1].pkt_tail->timestamp > end_time)
	    end_time = _stream[1].pkt_tail->timestamp;
	
	fprintf(f, "<flow aggregate='%u' src='%s' sport='%d' dst='%s' dport='%d' begin='%ld.%06ld' duration='%ld.%06ld'",
		_aggregate, _flowid.saddr().s().cc(), ntohs(_flowid.sport()),
		_flowid.daddr().s().cc(), ntohs(_flowid.dport()),
		_init_time.tv_sec, _init_time.tv_usec,
		end_time.tv_sec, end_time.tv_usec);
	if (_filepos)
	    fprintf(f, " filepos='%s'", String(_filepos).cc());
	fprintf(f, ">\n");

	if (_stream[0].have_ack_latency && _stream[1].have_ack_latency) {
	    timeval min_rtt = _stream[0].min_ack_latency + _stream[1].min_ack_latency;
	    fprintf(f, "  <rtt source='minacklatency' value='%ld.%06ld' />\n", min_rtt.tv_sec, min_rtt.tv_usec);
	}
	
	_stream[0].write_xml(this, f, cf->write_ack_latency(), cf->write_full_rcv_window());
	_stream[1].write_xml(this, f, cf->write_ack_latency(), cf->write_full_rcv_window());
	
	fprintf(f, "</flow>\n");
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
	np->end_seq = np->seq + calculate_seqlen(iph, tcph);
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
	if (np->seq != np->end_seq)
	    stream.pkt_data_tail = np;

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
	else if (ack != ack_stream.max_ack)
	    k->flags |= Pkt::F_ACK_REORDER;
	
	// find acked packet
	if (Pkt *acked_pkt = ack_stream.find_acked_pkt(ack, k->timestamp)) {
	    
	    struct timeval latency = k->timestamp - acked_pkt->timestamp;
	    if (!ack_stream.have_ack_latency || latency < ack_stream.min_ack_latency) {
		ack_stream.have_ack_latency = true;
		ack_stream.min_ack_latency = latency;
	    }
	    
	    // check whether this acknowledges something in the last loss
	    // event; if so, we should output the loss event
	    if (ack_stream.loss.type != NO_LOSS
		&& SEQ_GT(ack, ack_stream.loss.seq)) {
		// check for a false loss event: we don't believe the ack
		// could have seen the retransmitted packet yet
		if (k->timestamp - ack_stream.loss.end_time < 0.6 * ack_stream.min_ack_latency
		    && ack_stream.have_ack_latency)
		    ack_stream.loss.type = FALSE_LOSS;
		ack_stream.output_loss(this, cf);
	    }
	}
    }

    // did packet fill receive window?
    if (k->end_seq == ack_stream.end_rcv_window) {
	k->flags |= Pkt::F_FILLS_RCV_WINDOW;
	_stream[direction].filled_rcv_window = true;
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
	_stream[direction].update_counters(k, p->tcp_header(), p->transport_length(), this);

	// update counters, maximum sequence numbers, and so forth
	post_update_state(p, k, parent);
    }
}


// CALCULATEFLOWS PROPER

CalculateFlows::CalculateFlows()
    : Element(1, 1), _tipfd(0), _tipsd(0), _traceinfo_file(0), _filepos_h(0),
      _free_pkt(0), _packet_source(0)
{
    MOD_INC_USE_COUNT;
}

CalculateFlows::~CalculateFlows()
{
    MOD_DEC_USE_COUNT;
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
    delete _filepos_h;
}

void
CalculateFlows::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int 
CalculateFlows::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *af_element = 0, *tipfd_element = 0, *tipsd_element = 0;
    bool acklatency = false, ip_id = true, full_rcv_window = false;
    if (cp_va_parse(conf, this, errh,
		    cpOptional,
		    cpFilename, "output connection info file", &_traceinfo_filename,
		    cpKeywords,
		    "TRACEINFO", cpFilename, "output connection info file", &_traceinfo_filename,
		    "SOURCE", cpElement, "packet source element", &_packet_source,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "SUMMARYDUMP", cpElement,  "ToIPSummaryDump element for loss annotations", &tipsd_element,
		    "FLOWDUMPS", cpElement,  "ToIPFlowDumps element for loss annotations", &tipfd_element,
		    "ACKLATENCY", cpBool, "output ack latency XML?", &acklatency,
		    "FULLRCVWINDOW", cpBool, "output receive window fillers?", &full_rcv_window,
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
    if (tipsd_element && !(_tipsd = (ToIPSummaryDump *)(tipfd_element->cast("ToIPSummaryDump"))))
	return errh->error("SUMMARYDUMP must be a ToIPSummaryDump element");

    _ip_id = ip_id;
    _ack_latency = acklatency;
    _full_rcv_window = full_rcv_window;
    return 0;
}

int
CalculateFlows::initialize(ErrorHandler *errh)
{
    if (!_traceinfo_filename)
	/* nada */;
    else if (_traceinfo_filename == "-")
	_traceinfo_file = stdout;
    else if (!(_traceinfo_file = fopen(_traceinfo_filename.cc(), "w")))
	return errh->error("%s: %s", _traceinfo_filename.cc(), strerror(errno));
    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "<?xml version='1.0' standalone='yes'?>\n\
<trace");
	if (_tipfd)
	    fprintf(_traceinfo_file, " flowfilepattern='%s'",
		    _tipfd->output_pattern().cc());
	if (String s = HandlerCall::call_read(_packet_source, "filename").trim_space())
	    fprintf(_traceinfo_file, " file='%s'", s.cc());
	else if (_tipsd && _tipsd->filename())
	    fprintf(_traceinfo_file, " file='%s'", _tipsd->filename().cc());
	fprintf(_traceinfo_file, ">\n");
	HandlerCall::reset_read(_filepos_h, _packet_source, "packet_filepos");
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
    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "</trace>\n");
	fclose(_traceinfo_file);
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
	    if ((loss = new ConnInfo(p, _filepos_h)))
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


ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateFlows)
#include <click/bighashmap.cc>
CLICK_ENDDECLS
