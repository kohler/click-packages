// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>
#include "tcpcollector.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include "elements/analysis/aggregateipflows.hh"
CLICK_DECLS


/*******************************/
/* PACKET PROCESSING           */
/*                             */
/*******************************/

void
TCPCollector::StreamInfo::process_data(Pkt *k, const Packet *p, ConnInfo *conn)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header()));
    
    const click_ip *iph = p->ip_header();
    const click_tcp *tcph = p->tcp_header();

    // set fields appropriately
    k->data_packetno = total_packets - ack_packets;
    k->seq = ntohl(tcph->th_seq) - init_seq;
    k->end_seq = k->seq + calculate_seqlen(iph, tcph);
    k->ack = ntohl(tcph->th_ack) - conn->stream(!direction)->init_seq;
    if (!(tcph->th_flags & TH_ACK))
	k->ack = 0;
    k->ip_id = (parent->_ip_id ? iph->ip_id : 0);
    k->timestamp = p->timestamp_anno() - conn->init_time();
    k->packetno_anno = PACKET_NUMBER_ANNO(p, 0);
    k->flags = 0;

    // update counters
    total_packets++;
    total_seq += k->end_seq - k->seq;
    if (k->end_seq - k->seq == 0)
	ack_packets++;
    
    // SYN processing
    if (tcph->th_flags & TH_SYN) {
	if (have_syn && syn_seq != k->seq)
	    different_syn = true;
	else {
	    syn_seq = k->seq;
	    have_syn = true;
	}
    }

    // FIN processing
    if (tcph->th_flags & TH_FIN) {
	if (have_fin && fin_seq != k->end_seq - 1)
	    different_fin = true;
	else {
	    fin_seq = k->end_seq - 1;
	    have_fin = true;
	}
    }

    // update max_seq
    if (SEQ_GT(k->end_seq, max_seq))
	max_seq = np->end_seq;

    // process options, if there are any
    process_options(tcph, p->transport_length());

    // update end_rcv_window
    end_rcv_window = k->ack + (ntohs(tcph->th_win) << rcv_window_scale);
}

void
TCPCollector::StreamInfo::process_options(const click_tcp *tcph, int transport_length)
{
    // option processing; ignore timestamp
    int hlen = ((int)(tcph->th_off << 2) < transport_length ? tcph->th_off << 2 : transport_length);
    if (hlen > 20 
	&& (hlen != 32
	    || *(reinterpret_cast<const uint32_t *>(tcph + 1)) != htonl(0x0101080A))) {
	const uint8_t *oa = reinterpret_cast<const uint8_t *>(tcph);
	for (int oi = 20; oi < hlen; ) {
	    if (oa[oi] == TCPOPT_NOP) {
		oi++;
		continue;
	    } else if (oa[oi] == TCPOPT_EOL)
		break;

	    int xlen = oa[oi+1];
	    if (xlen < 2 || oi + xlen > hlen) // bad option
		break;

	    if (oa[oi] == TCPOPT_WSCALE && xlen == TCPOLEN_WSCALE && (tcph->th_flags & TH_SYN))
		rcv_window_scale = (oa[oi+2] <= 14 ? oa[oi+2] : 14);
	    else if (oa[oi] == TCPOPT_SACK_PERMITTED && xlen == TCPOLEN_SACK_PERMITTED)
		sent_sackok = true;

	    oi += xlen;
	}
    }
}

void
TCPCollector::StreamInfo::process_ack(Pkt *k, const Packet *p, StreamInfo &stream)
{
    // update acknowledgment information
    if (SEQ_GT(k->ack, max_ack))
	max_ack = k->ack;
    else if (k->ack != max_ack) {
	k->flags |= Pkt::F_ACK_NONORDERED;
	for (Pkt *prev = k->prev; prev && SEQ_LT(k->ack, prev->ack); prev = prev->prev)
	    prev->flags |= Pkt::F_ACK_NONORDERED | Pkt::F_ACK_REORDER;
    }

    // did packet fill receive window? was it a window probe?
    if (k->end_seq == end_rcv_window) {
	k->flags |= Pkt::F_FILLS_RCV_WINDOW;
	stream.filled_rcv_window = true;
    } else if (k->seq == end_rcv_window
	       && k->prev) {	// first packet never a window probe
	k->flags |= Pkt::F_WINDOW_PROBE;
	stream.sent_window_probe = true;
    }
}

void
TCPCollector::StreamInfo::attach_packet(Pkt *np)
{
    assert(np->flags == 0);
    assert(!np->prev || np->timestamp >= np->prev->timestamp);

    // hook up to packet list
    np->next = 0;
    np->prev = pkt_tail;
    if (pkt_tail)
	pkt_tail = pkt_tail->next = np;
    else
	pkt_head = pkt_tail = np;
    
    if (np->seq == np->end_seq)
	// exit if this is a pure ack
	// NB pure acks will not include IP ID check for network duplicates
	return;
    else
	pkt_data_tail = np;
    
    // exit if there is any new data
    if (SEQ_GT(np->end_seq, max_seq)) {
	np->flags |= Pkt::F_NEW;
	if (SEQ_LT(np->seq, max_seq))
	    np->flags |= Pkt::F_DUPDATA;
	return;
    }

    // Otherwise, it is a reordering, or possibly a retransmission.
    // Find the most relevant previous transmission of overlapping data.
    Pkt *x;
    int sequence = 0;
    for (x = np->prev; x; x = x->prev) {

	sequence++;
	
	if ((x->flags & Pkt::F_NEW) && SEQ_LEQ(x->end_seq, np->seq)) {
	    // 'x' is the first packet whose newest data is as old or older
	    // than our oldest data. Nothing relevant can precede it.
	    // Either we have a retransmission or a reordering.
	    break;

	} else if (np->seq == np->end_seq) {
	    // ignore pure acks
	
	} else if (np->seq == x->seq) {
	    // this packet overlaps with our data
	    np->flags |= Pkt::F_DUPDATA;
	    
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

	    break;
	    
	} else if ((SEQ_LEQ(x->seq, np->seq) && SEQ_LT(np->seq, x->end_seq))
		   || (SEQ_LT(x->seq, np->end_seq) && SEQ_LEQ(np->end_seq, x->end_seq))) {
	    // partial retransmission. There might be a more relevant
	    // preceding retransmission, so keep searching for one.
	    np->flags |= Pkt::F_DUPDATA;
	}
    }
    
    // intervening packets are in a non-ordered event
    for (x = (x ? x->next : pkt_head); x; x = x->next)
	x->flags |= Pkt::F_NONORDERED;
}

void
TCPCollector::ConnInfo::handle_packet(const Packet *p, TCPCollector *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    _clean = false;

    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    StreamInfo &stream = _stream[direction];
    StreamInfo &ack_stream = _stream[!direction];

    // set initial timestamp
    if (!timerisset(&_init_time))
	_init_time = p->timestamp_anno() - make_timeval(0, 1);

    // set initial sequence numbers
    if (!stream.have_init_seq) {
	stream.init_seq = ntohl(tcph->th_seq);
	stream.have_init_seq = true;
    }
    if ((tcph->th_flags & TH_ACK) && !ack_stream.have_init_seq) {
	ack_stream.init_seq = ntohl(tcph->th_ack);
	ack_stream.have_init_seq = true;
    }

    // check for timestamp confusion
    struct timeval timestamp = p->timestamp_anno() - _init_time;
    if (stream.pkt_tail && timestamp < stream.pkt_tail->timestamp) {
	stream.time_confusion = true;
	return;
    }

    // create and populate packet
    Pkt *k = parent->new_pkt();
    if (!k)			// out of memory
	return;
    
    stream.process_data(k, p, this);
    ack_stream.process_ack(k, p, stream);

    // attach packet to stream
    stream.attach_packet(k);
}




/*******************************/
/* FLOW PROCESSING             */
/*                             */
/*******************************/

TCPCollector::StreamInfo::StreamInfo()
    : have_init_seq(false), have_syn(false), different_syn(false),
      have_fin(false), different_fin(false),
      filled_rcv_window(false),
      sent_window_probe(false), sent_sackok(false), time_confusion(false),
      init_seq(0), max_seq(0), max_ack(0),
      total_packets(0), ack_packets(0), total_seq(0),
      end_rcv_window(0), rcv_window_scale(0),
      pkt_head(0), pkt_tail(0), pkt_data_tail(0)
{
}

TCPCollector::ConnInfo::ConnInfo(const Packet *p, const HandlerCall *filepos_call)
    : _aggregate(AGGREGATE_ANNO(p)), _finished(false), _clean(true)
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




/*******************************/
/* UNPARSING                   */
/*                             */
/*******************************/

void
TCPCollector::StreamInfo::write_full_rcv_window_xml(FILE *f) const
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
TCPCollector::StreamInfo::write_window_probe_xml(FILE *f) const
{
    if (sent_window_probe) {
	fprintf(f, "    <windowprobe>\n");
	for (Pkt *k = pkt_head; k; k = k->next)
	    if (k->flags & Pkt::F_WINDOW_PROBE)
		fprintf(f, "%ld.%06ld %u\n", k->timestamp.tv_sec, k->timestamp.tv_usec, k->end_seq);
	fprintf(f, "    </windowprobe>\n");
    }
}

void
TCPCollector::StreamInfo::write_packets_xml(FILE *f) const
{
    fprintf(f, "    <packet>\n");
    for (Pkt *k = pkt_head; k; k = k->next)
	fprintf(f, "%ld.%06ld %u %u %u\n", k->timestamp.tv_sec, k->timestamp.tv_usec, k->seq, k->end_seq - k->seq, k->ack);
    fprintf(f, "    </packet>\n");
}

void
TCPCollector::StreamInfo::write_xml(ConnInfo *conn, FILE *f, WriteFlags write_flags) const
{
    fprintf(f, "  <stream dir='%d' ndata='%u' nack='%u' beginseq='%u' seqlen='%u'",
	    direction, total_packets - ack_packets, ack_packets,
	    init_seq, total_seq);
    if (sent_sackok)
	fprintf(f, " sentsackok='yes'");
    if (different_syn)
	fprintf(f, " differentsyn='yes'");
    if (different_fin)
	fprintf(f, " differentfin='yes'");
    if (time_confusion)
	fprintf(f, " timeconfusion='yes'");

    if (((write_flags & WR_FULLRCVWND) && filled_rcv_window)
	|| ((write_flags & WR_WINDOWPROBE) && sent_window_probe)
	|| (write_flags & WR_PACKETS)) {
	fprintf(f, ">\n");
	if (write_flags & WR_FULLRCVWND)
	    write_full_rcv_window_xml(f);
	if (write_flags & WR_WINDOWPROBE)
	    write_window_probe_xml(f);
	if (write_flags & WR_PACKETS)
	    write_packets_xml(f);
	fprintf(f, "  </stream>\n");
    } else
	fprintf(f, " />\n");
}

void
TCPCollector::ConnInfo::kill(TCPCollector *cf)
{
    finish(cf);
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

	_stream[0].write_xml(this, f, cf->write_flags());
	_stream[1].write_xml(this, f, cf->write_flags());
	
	fprintf(f, "</flow>\n");
    }
    cf->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    cf->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    delete this;
}




/*******************************/
/* UNPARSING                   */
/*                             */
/*******************************/

TCPCollector::TCPCollector()
    : Element(1, 1), _traceinfo_file(0), _filepos_h(0),
      _free_pkt(0), _packet_source(0)
{
    MOD_INC_USE_COUNT;
}

TCPCollector::~TCPCollector()
{
    MOD_DEC_USE_COUNT;
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
    delete _filepos_h;
}

void
TCPCollector::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int 
TCPCollector::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *af_element = 0;
    bool ip_id = true, full_rcv_window = false, window_probe = false, packets = false;
    if (cp_va_parse(conf, this, errh,
		    cpOptional,
		    cpFilename, "output connection info file", &_traceinfo_filename,
		    cpKeywords,
		    "TRACEINFO", cpFilename, "output connection info file", &_traceinfo_filename,
		    "SOURCE", cpElement, "packet source element", &_packet_source,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    "FULLRCVWINDOW", cpBool, "output receive window fillers XML?", &full_rcv_window,
		    "WINDOWPROBE", cpBool, "output window probes XML?", &window_probe,
		    "PACKET", cpBool, "output packet XML?", &packets,
		    "IP_ID", cpBool, "use IP ID to distinguish duplicates?", &ip_id,
		    0) < 0)
        return -1;
    
    AggregateIPFlows *af = 0;
    if (af_element && !(af = (AggregateIPFlows *)(af_element->cast("AggregateIPFlows"))))
	return errh->error("NOTIFIER must be an AggregateIPFlows element");
    else if (af)
	af->add_listener(this);

    _ip_id = ip_id;
    _write_flags = (full_rcv_window ? WR_FULLRCVWND : 0)
	| (window_probe ? WR_WINDOWPROBE : 0)
	| (packets ? WR_PACKETS : 0);
    return 0;
}

int
TCPCollector::initialize(ErrorHandler *errh)
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
TCPCollector::cleanup(CleanupStage)
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

TCPCollector::Pkt *
TCPCollector::new_pkt()
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
TCPCollector::simple_action(Packet *p)
{
    uint32_t aggregate = AGGREGATE_ANNO(p);
    if (aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())) {
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
TCPCollector::aggregate_notify(uint32_t aggregate, AggregateEvent event, const Packet *)
{
    if (event == DELETE_AGG)
	if (ConnInfo *tmploss = _conn_map.find(aggregate)) {
	    _conn_map.remove(aggregate);
	    tmploss->kill(this);
	}
}




/*******************************/
/* HANDLERS                    */
/*                             */
/*******************************/

enum { H_CLEAR };

int
TCPCollector::write_handler(const String &s, Element *e, void *thunk, ErrorHandler *errh)
{
    TCPCollector *cf = static_cast<TCPCollector *>(e);
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
TCPCollector::add_handlers()
{
    add_write_handler("clear", write_handler, (void *)H_CLEAR);
}

ELEMENT_REQUIRES(userlevel false)
EXPORT_ELEMENT(TCPCollector)
#include <click/bighashmap.cc>
CLICK_ENDDECLS
