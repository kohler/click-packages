// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>
#include "tcpcollector.hh"
#include <click/error.hh>
#include <click/hashtable.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include <click/handlercall.hh>
#include "elements/analysis/aggregateipflows.hh"
#if TCPCOLLECTOR_XML
# include <algorithm>
# include <functional>
#endif
CLICK_DECLS


/*******************************/
/* HELPERS                     */
/*                             */
/*******************************/

Timestamp
TCPCollector::Conn::duration() const
{
    Timestamp d = (_stream[0]->pkt_tail ? _stream[0]->pkt_tail->timestamp : _init_time);
    if (_stream[1]->pkt_tail && _stream[1]->pkt_tail->timestamp > d)
	d = _stream[1]->pkt_tail->timestamp;
    return d;
}


/*******************************/
/* PACKET PROCESSING           */
/*                             */
/*******************************/

TCPCollector::Pkt *
TCPCollector::new_pkt()
{
    if (!_free_pkt)
	if (char* pktbuf = new char[_pkt_size * 1024]) {
	    _pktbuf_bank.push_back(pktbuf);
	    for (int i = 0; i < 1024; i++, pktbuf += _pkt_size) {
		Pkt *p = reinterpret_cast<Pkt*>(pktbuf);
		p->next = _free_pkt;
		_free_pkt = p;
	    }
#if TCPCOLLECTOR_MEMSTATS
	    _memusage += _pkt_size * 1024;
	    if (_memusage > _max_memusage)
		_max_memusage = _memusage;
#endif
	}
    if (_free_pkt) {
	Pkt *p = _free_pkt;
	_free_pkt = p->next;
	p->next = p->prev = 0;
	return p;
    } else
	return 0;
}

void
TCPCollector::Stream::process_data(Pkt* k, const Packet* p, Conn* conn)
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
    k->sack = 0;
    k->ip_id = (conn->ip_id() ? iph->ip_id : 0);
    k->timestamp = p->timestamp_anno() - conn->init_time();
    k->packetno_anno = PACKET_NUMBER_ANNO(p);
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

    // process options, if there are any
    // (do this before end_rcv_window, to get any rcv_window_scale)
    process_options(tcph, p->transport_length(), k, conn);

    // update end_rcv_window
    end_rcv_window = k->ack + (ntohs(tcph->th_win) << rcv_window_scale);

    // check packet length
    if (iph->ip_off & IP_MF)
	k->flags |= Pkt::F_FRAGMENT;
    if (ntohs(iph->ip_len) > mtu)
	mtu = ntohs(iph->ip_len);
}

void
TCPCollector::Stream::process_options(const click_tcp* tcph, int transport_length, Pkt* k, Conn* conn)
{
    // option processing; ignore timestamp
    int hlen = ((int)(tcph->th_off << 2) < transport_length ? tcph->th_off << 2 : transport_length);
    if (hlen > (int) sizeof(click_tcp)
	&& (hlen != 32
	    || *(reinterpret_cast<const uint32_t *>(tcph + 1)) != htonl(0x0101080A))) {
	const uint8_t* opt = reinterpret_cast<const uint8_t*>(tcph + 1);
	const uint8_t* end_opt = opt + hlen - sizeof(click_tcp);

	int nsack = 0;
	while (opt < end_opt) {
	    if (*opt == TCPOPT_NOP) {
		opt++;
		continue;
	    } else if (*opt == TCPOPT_EOL || opt + 1 > end_opt || opt + opt[1] > end_opt || opt[1] < 2)
		break;

	    if (*opt == TCPOPT_WSCALE && opt[1] == TCPOLEN_WSCALE && (tcph->th_flags & TH_SYN))
		rcv_window_scale = (opt[2] <= 14 ? opt[2] : 14);
	    else if (*opt == TCPOPT_SACK_PERMITTED && opt[1] == TCPOLEN_SACK_PERMITTED)
		sent_sackok = true;
	    else if (*opt == TCPOPT_SACK && (opt[1] % 8) == 2)
		nsack += (opt[1] - 2) / 4;
	    opt += opt[1];
	}

	// store any sack options in the packet record
	if (nsack && (k->sack = conn->allocate_sack(nsack + 1))) {
	    uint32_t* sack = k->sack;
	    *sack++ = nsack;
	    tcp_seq_t init_ack = conn->stream(!direction)->init_seq;
	    opt = reinterpret_cast<const uint8_t*>(tcph + 1);
	    while (opt < end_opt) {
		if (*opt == TCPOPT_NOP) {
		    opt++;
		    continue;
		} else if (*opt == TCPOPT_EOL || opt + 1 > end_opt || opt + opt[1] > end_opt || opt[1] < 2)
		    break;
		if (*opt == TCPOPT_SACK && (opt[1] % 8) == 2) {
		    const uint8_t* end_sack = opt + opt[1];
		    for (opt += 2; opt < end_sack; opt += 4, sack++) {
			memcpy(sack, opt, 4);
			*sack = ntohl(*sack) - init_ack;
		    }
		} else
		    opt += opt[1];
	    }

	    // now clean up the data
	    // first sort sack blocks
	    uint32_t* end_sack = k->sack + *k->sack + 1;
	    for (sack = k->sack + 1; sack < end_sack; sack += 2) {
		uint32_t* min_sack = sack;
		for (uint32_t* trav = min_sack + 2; trav < end_sack; trav += 2)
		    if (SEQ_LT(trav[0], min_sack[0]))
			min_sack = trav;
		if (min_sack != sack) {
		    uint32_t tmp[2];
		    memcpy(&tmp[0], min_sack, 8);
		    memcpy(min_sack, sack, 8);
		    memcpy(sack, &tmp[0], 8);
		}
	    }

	    // then compress overlapping ranges
	    uint32_t delta = 2;
	    for (sack = k->sack + 1; sack < end_sack; sack += 2) {
		if (delta != 2)
		    memcpy(sack, sack + delta - 2, 8);
		while (sack + delta < end_sack && SEQ_LEQ(sack[delta], sack[1])) {
		    if (SEQ_LEQ(sack[1], sack[delta+1]))
			sack[1] = sack[delta+1];
		    delta += 2;
		}
	    }
	    *k->sack -= delta - 2;
	}
    }
}

void
TCPCollector::Stream::process_ack(Pkt* k, const Packet*, Stream* stream)
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
	stream->filled_rcv_window = true;
    } else if (k->seq == end_rcv_window
	       && k->prev) {	// first packet never a window probe
	k->flags |= Pkt::F_WINDOW_PROBE;
	stream->sent_window_probe = true;
    }
}

void
TCPCollector::Stream::attach_packet(Pkt* k)
{
    assert(!(k->flags & (Pkt::F_NEW | Pkt::F_NONORDERED)));
    assert(!k->prev || k->timestamp >= k->prev->timestamp);

    // hook up to packet list
    k->next = 0;
    k->prev = pkt_tail;
    if (pkt_tail)
	pkt_tail = pkt_tail->next = k;
    else
	pkt_head = pkt_tail = k;

    if (k->seq == k->end_seq)
	// exit if this is a pure ack
	// NB pure acks will not include IP ID check for network duplicates
	return;
    else
	pkt_data_tail = k;

    // exit if there is any new data
    if (SEQ_GT(k->end_seq, max_seq)) {
	k->flags |= Pkt::F_NEW;
	if (SEQ_LT(k->seq, max_seq))
	    k->flags |= Pkt::F_DUPDATA;
	return;
    }

    // Otherwise, it is a reordering, or possibly a retransmission.
    // Find the most relevant previous transmission of overlapping data.
    Pkt *x;
    for (x = k->prev; x; x = x->prev) {
	if ((x->flags & Pkt::F_NEW) && SEQ_LEQ(x->end_seq, k->seq)) {
	    // 'x' is the first packet whose newest data is as old or older
	    // than our oldest data. Nothing relevant can precede it.
	    break;

	} else if (x->seq == x->end_seq) {
	    // ignore pure acks

	} else if (k->seq == x->seq && k->end_seq == x->end_seq
		   && k->ip_id && k->ip_id == x->ip_id) {
	    // network duplicate
	    k->flags |= Pkt::F_DUPDATA | Pkt::F_DUPLICATE;
	    return;

	} else if (k->seq == x->seq
		   || (SEQ_LEQ(x->seq, k->seq) && SEQ_LT(k->seq, x->end_seq))
		   || (SEQ_LT(x->seq, k->end_seq) && SEQ_LEQ(k->end_seq, x->end_seq))) {
	    // retransmission or partial retransmission
	    k->flags |= Pkt::F_DUPDATA;
	    break;
	}
    }

    // intervening packets are in a non-ordered event
    for (x = (x ? x->next : pkt_head); x; x = x->next)
	x->flags |= Pkt::F_NONORDERED;
}

void
TCPCollector::Conn::handle_packet(const Packet *p, TCPCollector *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    _clean = false;

    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    Stream* stream = _stream[direction];
    Stream* ack_stream = _stream[!direction];

    // set initial timestamp
    if (!_init_time)
	_init_time = p->timestamp_anno() - Timestamp::epsilon();

    // set initial sequence numbers
    if (!stream->have_init_seq) {
	stream->init_seq = ntohl(tcph->th_seq);
	stream->have_init_seq = true;
    }
    if ((tcph->th_flags & TH_ACK) && !ack_stream->have_init_seq) {
	ack_stream->init_seq = ntohl(tcph->th_ack);
	ack_stream->have_init_seq = true;
    }

    // check for timestamp confusion
    Timestamp timestamp = p->timestamp_anno() - _init_time;
    if (stream->pkt_tail && timestamp < stream->pkt_tail->timestamp) {
	stream->time_confusion = true;
	return;
    }

    // create and populate packet
    Pkt *k = parent->new_pkt();
    if (!k)			// out of memory
	return;

    stream->process_data(k, p, this);
    ack_stream->process_ack(k, p, stream);

    // attach packet to stream
    stream->attach_packet(k);

    // update max_seq
    if (SEQ_GT(k->end_seq, stream->max_seq))
	stream->max_seq = k->end_seq;
}

uint32_t*
TCPCollector::Conn::allocate_sack(int amount)
{
    if (amount < 0 || amount > SACKBuf::SACKBUFSIZ)
	return 0;
    if (!_sackbuf || _sackbuf->pos + amount > SACKBuf::SACKBUFSIZ) {
	if (SACKBuf* nbuf = new SACKBuf) {
	    nbuf->next = _sackbuf;
	    nbuf->pos = 0;
	    _sackbuf = nbuf;
	} else
	    return 0;
    }
    uint32_t* ptr = &_sackbuf->buf[_sackbuf->pos];
    _sackbuf->pos += amount;
    return ptr;
}



/*******************************/
/* FLOW PROCESSING             */
/*                             */
/*******************************/

TCPCollector::Stream::Stream(unsigned direction_)
    : direction(direction_),
      have_init_seq(false), have_syn(false), different_syn(false),
      have_fin(false), different_fin(false),
      filled_rcv_window(false),
      sent_window_probe(false), sent_sackok(false), time_confusion(false),
      init_seq(0), max_seq(0), max_ack(0),
      total_packets(0), ack_packets(0), total_seq(0),
      end_rcv_window(0), rcv_window_scale(0), mtu(0),
      pkt_head(0), pkt_tail(0), pkt_data_tail(0)
{
}

TCPCollector::Conn::Conn(const Packet* p, const HandlerCall* filepos_call, bool ip_id, Stream* stream0, Stream* stream1)
    : _aggregate(AGGREGATE_ANNO(p)), _ip_id(ip_id), _clean(true), _sackbuf(0)
{
    assert(_aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header())
	   && p->transport_length() >= (int)sizeof(click_udp));
    _flowid = IPFlowID(p);

    // set initial timestamp
    if (p->timestamp_anno())
	_init_time = p->timestamp_anno() - Timestamp::epsilon();

    // set file position
    if (filepos_call)
	_filepos = filepos_call->call_read().trim_space();

    _stream[0] = stream0;
    _stream[1] = stream1;
}

TCPCollector::Conn::~Conn()
{
    while (SACKBuf* s = _sackbuf) {
	_sackbuf = s->next;
	delete s;
    }
}

TCPCollector::Conn*
TCPCollector::new_conn(Packet* p)
    /* inserts new connection into _conn_map */
{
    char* connbuf = new char[_conn_size];
    char* stream0buf = new char[_stream_size];
    char* stream1buf = new char[_stream_size];
    if (connbuf && stream0buf && stream1buf) {
	Stream* stream0 = new((void*)stream0buf) Stream(0);
	Stream* stream1 = new((void*)stream1buf) Stream(1);
	Conn* conn = new((void*)connbuf) Conn(p, _filepos_h, _ip_id, stream0, stream1);
	for (int i = 0; i < _conn_attachments.size(); i++)
	    _conn_attachments[i]->new_conn_hook(conn, _conn_attachment_offsets[i]);
	for (int i = 0; i < _stream_attachments.size(); i++) {
	    _stream_attachments[i]->new_stream_hook(stream0, conn, _stream_attachment_offsets[i]);
	    _stream_attachments[i]->new_stream_hook(stream1, conn, _stream_attachment_offsets[i]);
	}
	_conn_map.set(AGGREGATE_ANNO(p), conn);
#if TCPCOLLECTOR_MEMSTATS
	_memusage += _conn_size + 2 * _stream_size;
	if (_memusage > _max_memusage)
	    _max_memusage = _memusage;
#endif
	return conn;
    } else {
	delete[] connbuf;
	delete[] stream0buf;
	delete[] stream1buf;
	return 0;
    }
}

#if TCPCOLLECTOR_MEMSTATS
uint32_t
TCPCollector::Conn::sack_memusage() const
{
    uint32_t mu = 0;
    for (SACKBuf *sackbuf = _sackbuf; sackbuf; sackbuf = sackbuf->next)
	mu += sizeof(SACKBuf);
    return mu;
}
#endif

void
TCPCollector::kill_conn(Conn* conn)
    /* DOES NOT delete connection from _conn_map */
{
#if TCPCOLLECTOR_XML
    if (_traceinfo_file)
	conn->write_xml(_traceinfo_file, this);
#endif
#if TCPCOLLECTOR_MEMSTATS
    // How many SACKBufs?
    uint32_t sack_memusage = conn->sack_memusage();
    if (_memusage + sack_memusage > _max_memusage)
	_max_memusage = _memusage + sack_memusage;
    _memusage -= _conn_size + 2 * _stream_size;
#endif
    Stream* stream0 = conn->stream(0);
    Stream* stream1 = conn->stream(1);
    for (int i = _stream_attachments.size() - 1; i >= 0; i--) {
	_stream_attachments[i]->kill_stream_hook(stream0, conn, _stream_attachment_offsets[i]);
	_stream_attachments[i]->kill_stream_hook(stream1, conn, _stream_attachment_offsets[i]);
    }
    for (int i = _conn_attachments.size() - 1; i >= 0; i--)
	_conn_attachments[i]->kill_conn_hook(conn, _conn_attachment_offsets[i]);
    free_pkt_list(stream0->pkt_head, stream0->pkt_tail);
    stream0->~Stream();
    delete[] ((char*)stream0);
    free_pkt_list(stream1->pkt_head, stream1->pkt_tail);
    stream1->~Stream();
    delete[] ((char*)stream1);
    conn->~Conn();
    delete[] ((char*)conn);
}



#if TCPCOLLECTOR_XML

/*******************************/
/* XML HOOKS                   */
/*                             */
/*******************************/

int
TCPCollector::add_trace_xmlattr(const String &attrname, const String &value)
{
    if (std::find(_trace_xmlattr_name.begin(), _trace_xmlattr_name.end(), attrname) < _trace_xmlattr_name.end())
	return -1;
    _trace_xmlattr_name.push_back(attrname);
    _trace_xmlattr_value.push_back(value);
    return 0;
}

inline bool
TCPCollector::XMLHook::operator()(const XMLHook &other_hook) const
{
    return name == other_hook.name;
}

int
TCPCollector::add_xmlattr(Vector<XMLHook> &v, const XMLHook &in_hook)
{
    if (std::find_if(v.begin(), v.end(), in_hook) < v.end())
	return -1;
    v.push_back(in_hook);
    return 0;
}

int
TCPCollector::add_connection_xmlattr(const String &attrname, ConnectionXMLAttrHook hook, void *thunk)
{
    XMLHook x;
    x.name = attrname;
    x.hook.connection = hook;
    x.thunk = thunk;
    return add_xmlattr(_conn_xmlattr, x);
}

int
TCPCollector::add_connection_xmltag(const String &attrname, ConnectionXMLTagHook hook, void *thunk)
{
    XMLHook x;
    x.name = attrname;
    x.hook.connectiontag = hook;
    x.thunk = thunk;
    return add_xmlattr(_conn_xmltag, x);
}

int
TCPCollector::add_stream_xmlattr(const String &attrname, StreamXMLAttrHook hook, void *thunk)
{
    XMLHook x;
    x.name = attrname;
    x.hook.stream = hook;
    x.thunk = thunk;
    return add_xmlattr(_stream_xmlattr, x);
}

int
TCPCollector::add_stream_xmltag(const String &attrname, StreamXMLTagHook hook, void *thunk)
{
    XMLHook x;
    x.name = attrname;
    x.hook.streamtag = hook;
    x.thunk = thunk;
    return add_xmlattr(_stream_xmltag, x);
}

static String
xmlprotect(const String &str)
{
    const char *begin = str.begin();
    const char *end = str.end();
    const char *s = begin;
    StringAccum sa;
    while (s < end) {
	if (*s == '\'' || *s == '&') {
	    sa.append(begin, s);
	    sa << (*s == '\'' ? "&apos;" : "&amp;");
	    begin = s + 1;
	}
	s++;
    }
    if (begin == str.begin())
	return str;
    else {
	sa.append(begin, str.end());
	return sa.take_string();
    }
}

void
TCPCollector::Conn::write_xml(FILE *f, const TCPCollector *owner)
{
    Timestamp duration = this->duration();

    fprintf(f, "\n<flow aggregate='%u' src='%s' sport='%d' dst='%s' dport='%d' begin='" PRITIMESTAMP "' duration='" PRITIMESTAMP "'",
	    _aggregate,
	    _flowid.saddr().unparse().c_str(), ntohs(_flowid.sport()),
	    _flowid.daddr().unparse().c_str(), ntohs(_flowid.dport()),
	    _init_time.sec(), _init_time.subsec(),
	    duration.sec(), duration.subsec());

    if (_filepos)
	fprintf(f, " filepos='%s'", String(_filepos).c_str());

    for (const XMLHook *x = owner->_conn_xmlattr.begin(); x < owner->_conn_xmlattr.end(); x++)
	if (String value = x->hook.connection(this, x->name, x->thunk))
	    fprintf(f, " %s='%s'", x->name.c_str(), xmlprotect(value).c_str());

    fprintf(f, ">\n");

    for (const XMLHook *x = owner->_conn_xmltag.begin(); x < owner->_conn_xmltag.end(); x++)
	x->hook.connectiontag(f, this, x->name, x->thunk);

    _stream[0]->write_xml(f, this, owner);
    _stream[1]->write_xml(f, this, owner);

    fprintf(f, "</flow>\n");
}

void
TCPCollector::Stream::write_xml(FILE* f, Conn* conn, const TCPCollector* owner)
{
    fprintf(f, "  <stream dir='%d' ndata='%u' nack='%u' beginseq='%u' seqlen='%u' mtu='%u'",
	    direction, total_packets - ack_packets, ack_packets,
	    init_seq, total_seq, mtu);
    if (sent_sackok)
	fprintf(f, " sentsackok='yes'");
    if (different_syn)
	fprintf(f, " differentsyn='yes'");
    if (different_fin)
	fprintf(f, " differentfin='yes'");
    if (time_confusion)
	fprintf(f, " timeconfusion='yes'");

    for (const XMLHook *x = owner->_stream_xmlattr.begin(); x < owner->_stream_xmlattr.end(); x++)
	if (String value = x->hook.stream(this, conn, x->name, x->thunk))
	    fprintf(f, " %s='%s'", x->name.c_str(), xmlprotect(value).c_str());

    fprintf(f, ">\n");

    for (const XMLHook *x = owner->_stream_xmltag.begin(); x < owner->_stream_xmltag.end(); x++)
	x->hook.streamtag(f, this, conn, x->name, x->thunk);

    fprintf(f, "  </stream>\n");
}


// OPTIONAL STREAM XML TAGS

void
TCPCollector::Stream::packet_xmltag(FILE* f, Stream* stream, Conn*, const String& tagname, void*)
{
    if (stream->pkt_head) {
	fprintf(f, "    <%s>", tagname.c_str());
	for (Pkt *k = stream->pkt_head; k; k = k->next) {
	    fprintf(f, "\n" PRITIMESTAMP " %u %u %u", k->timestamp.sec(), k->timestamp.subsec(), k->seq, k->end_seq - k->seq, k->ack);
	    if (const uint32_t* sack = k->sack) {
		const uint32_t* end_sack = sack + *sack + 1;
		char sep = ' ';
		for (sack++; sack < end_sack; sack += 2, sep = ';')
		    fprintf(f, "%c%u-%u", sep, sack[0], sack[1]);
	    }
	}
	fprintf(f, "\n    </%s>\n", tagname.c_str());
    }
}

void
TCPCollector::Stream::fullrcvwindow_xmltag(FILE* f, Stream* stream, Conn*, const String& tagname, void*)
{
    if (stream->filled_rcv_window) {
	fprintf(f, "    <%s>\n", tagname.c_str());
	for (Pkt *k = stream->pkt_head; k; k = k->next)
	    if (k->flags & Pkt::F_FILLS_RCV_WINDOW)
		fprintf(f, PRITIMESTAMP " %u\n", k->timestamp.sec(), k->timestamp.subsec(), k->end_seq);
	fprintf(f, "    </%s>\n", tagname.c_str());
    }
}

void
TCPCollector::Stream::windowprobe_xmltag(FILE* f, Stream* stream, Conn*, const String& tagname, void*)
{
    if (stream->sent_window_probe) {
	fprintf(f, "    <%s>\n", tagname.c_str());
	for (Pkt *k = stream->pkt_head; k; k = k->next)
	    if (k->flags & Pkt::F_WINDOW_PROBE)
		fprintf(f, PRITIMESTAMP " %u\n", k->timestamp.sec(), k->timestamp.subsec(), k->end_seq);
	fprintf(f, "    </%s>\n", tagname.c_str());
    }
}

void
TCPCollector::Stream::interarrival_xmltag(FILE* f, Stream* stream, Conn*, const String& tagname, void*)
{
    if (stream->pkt_head) {
	fprintf(f, "    <%s>\n", tagname.c_str());
	for (Pkt *k = stream->pkt_head->next; k; k = k->next) {
	    Timestamp diff = k->timestamp - k->prev->timestamp;
	    fprintf(f, "%.0f\n", diff.doubleval() * 1e6);
	}
	fprintf(f, "    </%s>\n", tagname.c_str());
    }
}

#endif



/*******************************/
/* TOP LEVEL                   */
/*                             */
/*******************************/

TCPCollector::TCPCollector()
    : _free_pkt(0),
      _pkt_size(sizeof(Pkt)), _stream_size(sizeof(Stream)), _conn_size(sizeof(Conn)),
      _filepos_h(0), _packet_source(0)
#if TCPCOLLECTOR_XML
    , _traceinfo_file(0)
#endif
{
}

TCPCollector::~TCPCollector()
{
    for (int i = 0; i < _pktbuf_bank.size(); i++)
	delete[] _pktbuf_bank[i];
    delete _filepos_h;
}

int
TCPCollector::add_space(unsigned space, int& size)
{
    if (space == 0)
	return size;
    else if (space >= 0x1000000 || (int)(space + size) < 0 || _pktbuf_bank.size())
	return -1;
    else {
	int offset = size;
	size = (size + space + 7) & ~7;
	return offset;
    }
}

int
TCPCollector::add_pkt_attachment(unsigned space)
{
    return add_space(space, _pkt_size);
}

int
TCPCollector::add_stream_attachment(AttachmentManager* a, unsigned space)
{
    int off = add_space(space, _stream_size);
    if (off >= 0) {
	_stream_attachments.push_back(a);
	_stream_attachment_offsets.push_back(off);
    }
    return off;
}

int
TCPCollector::add_conn_attachment(AttachmentManager* a, unsigned space)
{
    int off = add_space(space, _conn_size);
    if (off >= 0) {
	_conn_attachments.push_back(a);
	_conn_attachment_offsets.push_back(off);
    }
    return off;
}

int
TCPCollector::configure(Vector<String> &conf, ErrorHandler *errh)
{
    AggregateIPFlows *af = 0;
    bool ip_id = true;
#if TCPCOLLECTOR_XML
    bool full_rcv_window = false, window_probe = false, packets = false, interarrival = false;
#endif
    if (Args(conf, this, errh)
#if TCPCOLLECTOR_XML
	.read_p("TRACEINFO", FilenameArg(), _traceinfo_filename)
#endif
	.read("NOTIFIER", ElementCastArg("AggregateIPFlows"), af)
	.read("SOURCE", _packet_source)
	.read("IP_ID", ip_id)
#if TCPCOLLECTOR_XML
	.read("FULLRCVWINDOW", full_rcv_window)
	.read("WINDOWPROBE", window_probe)
	.read("INTERARRIVAL", interarrival)
	.read("PACKET", packets)
#endif
	.complete() < 0)
        return -1;

    if (af)
	af->add_listener(this);

    _ip_id = ip_id;

#if TCPCOLLECTOR_XML
    if (packets)
	add_stream_xmltag("packet", Stream::packet_xmltag, 0);
    if (full_rcv_window)
	add_stream_xmltag("fullrcvwindow", Stream::fullrcvwindow_xmltag, 0);
    if (window_probe)
	add_stream_xmltag("windowprobe", Stream::windowprobe_xmltag, 0);
    if (interarrival)
	add_stream_xmltag("interarrival", Stream::interarrival_xmltag, 0);
#endif

    return 0;
}

int
TCPCollector::initialize(ErrorHandler *errh)
{
#if TCPCOLLECTOR_XML
    if (!_traceinfo_filename)
	/* nada */;
    else if (_traceinfo_filename == "-")
	_traceinfo_file = stdout;
    else if (!(_traceinfo_file = fopen(_traceinfo_filename.c_str(), "w")))
	return errh->error("%s: %s", _traceinfo_filename.c_str(), strerror(errno));

    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "<?xml version='1.0' standalone='yes'?>\n\
<trace");
	if (_packet_source)
	    if (String s = HandlerCall::call_read(_packet_source, "filename").trim_space())
		fprintf(_traceinfo_file, " file='%s'", xmlprotect(s).c_str());
	for (int i = 0; i < _trace_xmlattr_name.size(); i++)
	    fprintf(_traceinfo_file, " %s='%s'", _trace_xmlattr_name[i].c_str(), xmlprotect(_trace_xmlattr_value[i]).c_str());
	fprintf(_traceinfo_file, ">\n");
    }
#endif

    if (_packet_source)
	HandlerCall::reset_read(_filepos_h, _packet_source, "packet_filepos");

    return 0;
}

void
TCPCollector::cleanup(CleanupStage)
{
    for (ConnMap::iterator iter = _conn_map.begin(); iter.live(); iter++)
	kill_conn(iter.value());
    _conn_map.clear();

#if TCPCOLLECTOR_XML
    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "\n</trace>\n");
	fclose(_traceinfo_file);
    }
#endif
}

Packet *
TCPCollector::simple_action(Packet *p)
{
    uint32_t aggregate = AGGREGATE_ANNO(p);
    if (aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())) {
	Conn *conn = _conn_map.get(aggregate);
	if (!conn && !(conn = new_conn(p))) {
	    click_chatter("out of memory!");
	    p->kill();
	    return 0;
	}
	conn->handle_packet(p, this);
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
	if (Conn *conn = _conn_map.get(aggregate)) {
	    _conn_map.erase(aggregate);
	    kill_conn(conn);
	}
}



/*******************************/
/* HANDLERS                    */
/*                             */
/*******************************/

enum { H_CLEAR, H_FLUSH, H_MAX_MEMUSAGE };

#if TCPCOLLECTOR_MEMSTATS
String
TCPCollector::read_handler(Element *e, void *)
{
    TCPCollector *cf = static_cast<TCPCollector *>(e);
    return String(cf->_max_memusage) + "\n";
}
#endif

int
TCPCollector::write_handler(const String &, Element *e, void *thunk, ErrorHandler *)
{
    TCPCollector *cf = static_cast<TCPCollector *>(e);
    switch ((intptr_t)thunk) {
      case H_CLEAR:
	for (ConnMap::iterator i = cf->_conn_map.begin(); i.live(); i++)
	    cf->kill_conn(i.value());
	cf->_conn_map.clear();
	return 0;
#if TCPCOLLECTOR_XML
      case H_FLUSH:
	if (cf->_traceinfo_file)
	    fflush(cf->_traceinfo_file);
	return 0;
#endif
      default:
	return -1;
    }
}

void
TCPCollector::add_handlers()
{
    add_write_handler("clear", write_handler, (void *)H_CLEAR);
#if TCPCOLLECTOR_XML
    add_write_handler("flush", write_handler, (void *)H_FLUSH);
#endif
#if TCPCOLLECTOR_MEMSTATS
    add_read_handler("max_memusage", read_handler, (void *)H_MAX_MEMUSAGE);
#endif
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(TCPCollector)
CLICK_ENDDECLS
