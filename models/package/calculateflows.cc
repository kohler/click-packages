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
#include "elements/analysis/toipsumdump.hh"
CLICK_DECLS

CalculateFlows::StreamInfo::StreamInfo()
    : have_init_seq(false), have_syn(false), have_fin(false),
      have_ack_bounce(false),
      init_seq(0), max_seq(0), max_ack(0), max_live_seq(0), max_loss_seq(0),
      total_packets(0), total_seq(0),
      loss_events(0), possible_loss_events(0), false_loss_events(0),
      event_id(0),
      pkt_head(0), pkt_tail(0),
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
    // Find the most relevant previous transmission of overlapping data.
    Pkt *x = np->prev;
    Pkt *partial = 0;
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
	    if (partial) {
		np->flags |= Pkt::F_REXMIT | Pkt::F_STRANGE;
		register_loss_event(x, np, conn, parent);
	    } else
		np->flags |= Pkt::F_REORDER;
	    return;
	} else if ((SEQ_LEQ(x->seq, np->seq) && SEQ_LT(np->seq, x->last_seq))
		   || (SEQ_LT(x->seq, np->last_seq) && SEQ_LEQ(np->last_seq, x->last_seq))) {
	    // Odd partial retransmission. There might be a more relevant
	    // preceding retransmission, so keep searching for one.
	    partial = x;
	    x = x->prev;
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
    if (loss.type != NO_LOSS) // output any previous loss event
	output_loss(conn, parent);
    if (SEQ_GT(max_ack, endk->seq))
	loss.type = FALSE_LOSS;
    else if (SEQ_GEQ(endk->last_seq, max_live_seq))
	loss.type = POSSIBLE_LOSS;
    else
	loss.type = LOSS;
    loss.time = startk->timestamp;
    loss.seq = startk->seq;
    loss.end_time = endk->timestamp;
    loss.last_seq = max_live_seq;

    // We just completed a loss event, so reset max_live_seq and max_loss_seq.
    max_live_seq = endk->last_seq;
    if (SEQ_GT(max_seq, max_loss_seq))
	max_loss_seq = max_seq;
}

void
CalculateFlows::StreamInfo::update_counters(const Pkt *np, const click_tcp *tcph, const ConnInfo *conn)
{
    // update counters
    total_packets++;
    total_seq += np->last_seq - np->seq;
    
    // mark SYN and FIN packets
    if (tcph->th_flags & TH_SYN) {
	if (have_syn && syn_seq != np->seq)
	    click_chatter("%u: different SYN seqnos!", conn->aggregate()); // XXX report error
	else {
	    syn_seq = np->seq;
	    have_syn = true;
	}
    }
    if (tcph->th_flags & TH_FIN) {
	if (have_fin && fin_seq != np->last_seq - 1)
	    click_chatter("%u: different FIN seqnos!", conn->aggregate()); // XXX report error
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
	   << end_time << ' ' << last_seq;
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
	    sa << (last_seq + cstr->init_seq);
	else
	    sa << last_seq;
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

CalculateFlows::ConnInfo::ConnInfo(const Packet *p, const HandlerCall *filepos_call, Router *r)
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
	_filepos = filepos_call->call_read(r).trim_space();

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
       << end_time << "' lastseq='" << last_seq << "' />\n";
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
CalculateFlows::StreamInfo::write_xml(FILE *f) const
{
    fprintf(f, "  <flow dir='%d' beginseq='%u' seqlen='%u' nloss='%u' nploss='%u' nfloss='%u'",
	    direction, init_seq, total_seq, loss_events, possible_loss_events, false_loss_events);
    if (loss_trail) {
	fprintf(f, ">\n");
	loss_trail->write_xml(f);
	fprintf(f, "  </flow>\n");
    } else
	fprintf(f, " />\n");
}

void
CalculateFlows::ConnInfo::kill(CalculateFlows *cf)
{
    _stream[0].output_loss(this, cf);
    _stream[1].output_loss(this, cf);
    if (FILE *f = cf->conninfo_file()) {
	timeval end_time = (_stream[0].pkt_tail ? _stream[0].pkt_tail->timestamp : _init_time);
	if (_stream[1].pkt_tail && _stream[1].pkt_tail->timestamp > end_time)
	    end_time = _stream[1].pkt_tail->timestamp;
	
	fprintf(f, "<connection aggregate='%u' src='%s' sport='%d' dst='%s' dport='%d' begin='%ld.%06ld' duration='%ld.%06ld'",
		_aggregate, _flowid.saddr().s().cc(), ntohs(_flowid.sport()),
		_flowid.daddr().s().cc(), ntohs(_flowid.dport()),
		_init_time.tv_sec, _init_time.tv_usec,
		end_time.tv_sec, end_time.tv_usec);
	if (_filepos)
	    fprintf(f, " filepos='%s'", String(_filepos).cc());
	fprintf(f, ">\n");
	
	_stream[0].write_xml(f);
	_stream[1].write_xml(f);
	fprintf(f, "</connection>\n");
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
	    if (ack_stream.loss.type != NO_LOSS
		&& SEQ_GT(ack, ack_stream.loss.seq)) {
		// check for a false loss event: we don't believe the ack
		// could have seen the retransmitted packet yet
		if (k->timestamp - ack_stream.loss.end_time < 0.6 * ack_stream.min_ack_bounce
		    && ack_stream.have_ack_bounce)
		    ack_stream.loss.type = FALSE_LOSS;
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
	_stream[direction].update_counters(k, p->tcp_header(), this);

	// update counters, maximum sequence numbers, and so forth
	post_update_state(p, k, parent);
    }
}


// CALCULATEFLOWS PROPER

CalculateFlows::CalculateFlows()
    : Element(1, 1), _tipfd(0), _tipsd(0), _conninfo_file(0), _filepos_call(0),
      _free_pkt(0)
{
    MOD_INC_USE_COUNT;
}

CalculateFlows::~CalculateFlows()
{
    MOD_DEC_USE_COUNT;
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
    delete _filepos_call;
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
    bool ack_match = false, ip_id = true;
    if (cp_va_parse(conf, this, errh,
		    cpOptional,
		    cpFilename, "output connection info file", &_conninfo_filename,
		    cpKeywords,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "SUMMARYDUMP", cpElement,  "ToIPSummaryDump element for loss annotations", &tipsd_element,
		    "FLOWDUMPS", cpElement,  "ToIPFlowDumps element for loss annotations", &tipfd_element,
		    "CONNINFO", cpFilename, "output connection info file", &_conninfo_filename,
		    "CONNINFO_FILEPOS", cpReadHandlerCall, "output file position", &_filepos_call,
		    "CONNINFO_TRACEFILE", cpFilename, "input dump filename, for recording in STATFILE", &_conninfo_tracefile,
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
    if (tipsd_element && !(_tipsd = (ToIPSummaryDump *)(tipfd_element->cast("ToIPSummaryDump"))))
	return errh->error("SUMMARYDUMP must be a ToIPSummaryDump element");

    _ack_match = (ack_match && _tipfd);
    _ip_id = ip_id;
    return 0;
}

int
CalculateFlows::initialize(ErrorHandler *errh)
{
    if (!_conninfo_filename)
	/* nada */;
    else if (_conninfo_filename == "-")
	_conninfo_file = stdout;
    else if (!(_conninfo_file = fopen(_conninfo_filename.cc(), "w")))
	return errh->error("%s: %s", _conninfo_filename.cc(), strerror(errno));
    if (_conninfo_file) {
	fprintf(_conninfo_file, "<?xml version='1.0' standalone='yes'?>\n\
<connections");
	if (_tipfd)
	    fprintf(_conninfo_file, " flowfilepattern='%s'",
		    _tipfd->output_pattern().cc());
	if (_conninfo_tracefile)
	    fprintf(_conninfo_file, " tracefile='%s'", _conninfo_tracefile.cc());
	else if (_tipsd && _tipsd->filename())
	    fprintf(_conninfo_file, " tracefile='%s'", _tipsd->filename().cc());
	fprintf(_conninfo_file, ">\n");
    }

    // check handler call
    if (_filepos_call && _filepos_call->initialize_read(this, errh) < 0)
	return -1;

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
    if (_conninfo_file) {
	fprintf(_conninfo_file, "</connections>\n");
	fclose(_conninfo_file);
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
	    if ((loss = new ConnInfo(p, _filepos_call, router())))
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
