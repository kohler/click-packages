// -*- c-basic-offset: 4 -*-
#include <config.h>
#include <click/config.h>

#include "collectflows.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <click/click_ip.h>
#include <click/click_tcp.h>
#include <click/click_udp.h>
#include <click/packet_anno.hh>

// flow

bool
CollectTCPFlows::Flow::make_pair(const IPFlowID &flow, Flow **flow1, Flow **flow2)
{
    *flow1 = new Flow(flow, true);
    *flow2 = new Flow(flow.rev(), false);
    if (*flow1 && *flow2) {
	(*flow1)->_reverse = *flow2;
	(*flow2)->_reverse = *flow1;
	return true;
    } else {
	delete *flow1;
	delete *flow2;
	*flow1 = *flow2 = 0;
	return false;
    }
}

inline void
CollectTCPFlows::Flow::update(const Packet *p, CollectTCPFlows *cf)
{
    // check for TCP flags
    const click_tcp *tcph = p->tcp_header();
    if (IP_FIRSTFRAG(p->ip_header())) {
	if (tcph->th_flags & TH_RST)
	    set_session_over();
	else if (tcph->th_flags & TH_FIN)
	    set_flow_over();
	else if ((tcph->th_flags & TH_SYN) && session_over()) {
	    // write out session, clear state
	    cf->write_session(this);
	    clear(true);
	    reverse()->clear(false);
	}
    }
    
    _packet_count++;
    _byte_count += p->length() + EXTRA_LENGTH_ANNO(p);
    _last_ts = p->timestamp_anno();
    if (!_first_ts.tv_sec)	// XXX
	_first_ts = _last_ts;
}

// element

CollectTCPFlows::CollectTCPFlows()
    : Element(1, 1), _map(0), _f(0)
{
    MOD_INC_USE_COUNT;
}

CollectTCPFlows::~CollectTCPFlows()
{
    MOD_DEC_USE_COUNT;
}

void
CollectTCPFlows::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int
CollectTCPFlows::configure(Vector<String> &conf, ErrorHandler *errh)
{
    _gen_packets = false;
    _filename = String();
    if (cp_va_parse(conf, this, errh,
		    cpOptional,
		    cpFilename, "dump filename", &_filename,
		    cpKeywords,
		    "SESSION_PACKETS", cpBool, "generate session packets?", &_gen_packets,
		    0) < 0)
	return -1;
    if (_gen_packets && noutputs() == 1)
	errh->warning("`SESSION_PACKETS', but element has only 1 output");
    return 0;
}

int
CollectTCPFlows::initialize(ErrorHandler *errh)
{
    assert(!_f);
    if (!_filename)
	/* nada */;
    else if (_filename != "-") {
	_f = fopen(_filename, "wb");
	if (!_f)
	    return errh->error("%s: %s", _filename.cc(), strerror(errno));
    } else {
	_f = stdout;
	_filename = "<stdout>";
    }
    
    _last_flow = _done_head = _done_tail = 0;
    timerclear(&_done_timestamp);
    return 0;
}

void
CollectTCPFlows::cleanup(CleanupStage)
{
    if (_f && _f != stdout)
	fclose(_f);
    _f = 0;
    clear(false);
}

void
CollectTCPFlows::clear(bool write_flows)
{
    Vector<Flow *> poo;
    Flow *to_free = 0;

    for (Map::Iterator iter = _map.first(); iter; iter++)
	if (Flow *m = iter.value()) {
	    if (m->is_primary()) {
		m->_free_next = to_free;
		to_free = m;
		poo.push_back(m);
	    }
	}

    while (to_free) {
	assert(poo.back() == to_free);
	poo.pop_back();
	Flow *n = to_free->_free_next;
	if (write_flows)
	    write_session(to_free);
	delete to_free->reverse();
	delete to_free;
	to_free = n;
    }

    _map.clear();
    _last_flow = _done_head = _done_tail = 0;
}

Packet *
CollectTCPFlows::bad_packet(Packet *p)
{
    p->kill();
    return 0;
}

CollectTCPFlows::Flow *
CollectTCPFlows::add_flow(const IPFlowID &flowid, Packet *)
{
    Flow *flow1, *flow2;
    if (Flow::make_pair(flowid, &flow1, &flow2)) {
	_map.insert(flow1->flow_id(), flow1);
	_map.insert(flow2->flow_id(), flow2);
    } else
	click_chatter("%s: out of memory!", declaration().cc());
    return flow1;
}

inline CollectTCPFlows::Flow *
CollectTCPFlows::Flow::free_from_free(Map &map)
{
    // see also clear_map below
    //click_chatter("kill %s", reverse()->flow_id().rev().s().cc());
    Flow *next = _free_next;
    map.remove(flow_id());
    map.remove(reverse()->flow_id());
    delete reverse();
    delete this;
    return next;
}

void
CollectTCPFlows::pass_over_done(const struct timeval &ts)
{
    if (!_done_timestamp.tv_sec) {
	_done_timestamp = ts;
	return;
    }

    // determine left boundary for dead flows
    struct timeval kill_dead_since = _done_timestamp;
    kill_dead_since.tv_sec -= 120; // 2 minutes

    // pass over flows
    Flow *free_list = _done_head;
    Flow **prev_ptr = &free_list;

    Flow *flow = free_list;
    while (flow) {
	Flow *next = flow->free_next();
	if (!flow->session_over()) {
	    // reuse of a port; take it off the free-tracked list
	    *prev_ptr = next;
	    flow->clear_free_tracked();
	} else if (flow->used_since(kill_dead_since))
	    break;
	else
	    prev_ptr = &flow->_free_next;
	flow = next;
    }

    // cut off free_list before 'flow'
    *prev_ptr = 0;

    // move free_head forward, to 'flow' or beyond
    if (flow && flow->free_next()) {
	// if 'flow' exists, then shift it to the end of the list
	_done_head = flow->free_next();
	flow->_free_next = 0;
	flow->append_to_free(_done_head, _done_tail);
    } else
	_done_head = _done_tail = flow;

    // free contents of free_list
    while (free_list) {
	write_session(free_list);
	free_list = free_list->free_from_free(_map);
    }

    if (_done_head)
	_done_timestamp = _done_head->last_session_timestamp();
    _done_timestamp.tv_sec += 120;
}

Packet *
CollectTCPFlows::handle_packet(Packet *p)
{
    const click_ip *iph = p->ip_header();
    if (!iph)
	return bad_packet(p);

    IPFlowID flowid(p);
    Flow *flow = _map[flowid];

    if (!flow)
	flow = add_flow(flowid, p);
    if (flow) {
	flow->update(p, this);
	if (flow->session_over() && !flow->free_tracked())
	    flow->add_to_free_tracked_tail(_done_head, _done_tail);
    }

    if (timercmp(&p->timestamp_anno(), &_done_timestamp, >))
	pass_over_done(p->timestamp_anno());
    
    return p;
}

void
CollectTCPFlows::push(int, Packet *p)
{
    if (Packet *q = handle_packet(p))
	output(0).push(q);
}

Packet *
CollectTCPFlows::pull(int)
{
    Packet *p = input(0).pull();
    if (p)
	p = handle_packet(p);
    return p;
}

void
CollectTCPFlows::write_flow(const Flow *flow)
{
    if (_f) {
	StringAccum sa;
	sa << flow->first_session_timestamp() << ' '
	   << flow->last_session_timestamp() << ' '
	   << flow->_flow << ' ' << flow->_packet_count << ' '
	   << flow->_byte_count << '\n';
	fwrite(sa.data(), 1, sa.length(), _f);
    }

    if (_gen_packets) {
	int p = flow->protocol();
	WritablePacket *q = Packet::make(0, 0, sizeof(click_ip), sizeof(click_tcp));
	if (q) {
	    q->set_network_header(q->data(), sizeof(click_ip));
	    
	    click_ip *iph = q->ip_header();
	    iph->ip_v = 4;
	    iph->ip_hl = sizeof(click_ip) >> 2;
	    iph->ip_len = htons(q->length());
	    iph->ip_off = 0;
	    iph->ip_p = p;
	    iph->ip_src = flow->flow_id().saddr();
	    iph->ip_dst = flow->flow_id().daddr();

	    switch (p) {

	      case IP_PROTO_TCP: {
		  click_tcp *tcph = q->tcp_header();
		  q->put(sizeof(click_tcp));
		  tcph->th_sport = flow->flow_id().sport();
		  tcph->th_dport = flow->flow_id().dport();
		  tcph->th_off = sizeof(click_tcp) >> 2;
		  tcph->th_flags = TH_SYN | TH_FIN;
		  break;
	      }

	      case IP_PROTO_UDP: {
		  click_udp *udph = q->udp_header();
		  q->push(sizeof(click_udp));
		  udph->uh_sport = flow->flow_id().sport();
		  udph->uh_dport = flow->flow_id().dport();
		  udph->uh_ulen = ntohs(sizeof(click_udp));
		  break;
	      }
	      
	    }

	    SET_EXTRA_PACKETS_ANNO(q, flow->_packet_count - 1);
	    SET_EXTRA_LENGTH_ANNO(q, flow->_byte_count - q->length());
	    q->set_timestamp_anno(flow->_first_ts);
	    checked_output_push(1, q);
	}
    }
}

void
CollectTCPFlows::write_session(const Flow *flow)
{
    flow = flow->primary();
    if (flow->packet_count())
	write_flow(flow);
    flow = flow->reverse();
    if (flow->packet_count())
	write_flow(flow);
}

int
CollectTCPFlows::flush_handler(const String &, Element *e, void *, ErrorHandler *)
{
    CollectTCPFlows *ctf = static_cast<CollectTCPFlows *>(e);
    ctf->clear(true);
    return 0;
}

void
CollectTCPFlows::add_handlers()
{
    add_write_handler("flush", flush_handler, 0);
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CollectTCPFlows)

#include <click/bighashmap.cc>
