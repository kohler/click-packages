// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>
#include "tcpmystery.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include <algorithm>
#include <float.h>
#include "elements/analysis/aggregateipflows.hh"
#include "elements/analysis/toipsumdump.hh"
#include "tcpscoreboard.hh"
CLICK_DECLS


// Element setup     //
//                   //

TCPMystery::TCPMystery()
{
    MOD_INC_USE_COUNT;
}

TCPMystery::~TCPMystery()
{
    MOD_DEC_USE_COUNT;
}

int
TCPMystery::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *e;
    bool ackcausation = false, semirtt = false, rtt = true;
    if (cp_va_parse(conf, this, errh,
		    cpElement, "TCPCollector", &e,
		    cpKeywords,
		    "ACKCAUSATION", cpBool, "output ack causation XML?", &ackcausation,
		    "SEMIRTT", cpBool, "output semi-RTT XML?", &semirtt,
		    "RTT", cpBool, "output RTT XML?", &rtt,
		    cpEnd) < 0)
	return -1;
    TCPCollector *tcpc = (TCPCollector *)e->cast("TCPCollector");
    if (!tcpc)
	return errh->error("'%s' not a TCPCollector element", e->declaration().c_str());
    if (rtt)
	tcpc->add_connection_xmltag("rtt", mystery_rtt_xmltag, this);
    if (semirtt)
	tcpc->add_stream_xmltag("semirtt", mystery_semirtt_xmltag, this);
    if (ackcausation)
	tcpc->add_stream_xmltag("ackcausation", mystery_ackcausation_xmltag, this);
    _myconn_offset = tcpc->add_conn_attachment(this, sizeof(MyConn));
    _mypkt_offset = tcpc->add_pkt_attachment(sizeof(MyPkt));
    return 0;
}


// construction //

void
TCPMystery::new_conn_hook(Conn* c, unsigned)
{
    MyConn* mc = myconn(c);
    mc->_finished = false;
}

void
TCPMystery::clear(Stream* s)
{
    for (Pkt* k = s->pkt_head; k; k = k->next) {
	MyPkt* mk = mypkt(k);
	mk->flags = 0;
	mk->event_id = 0;
	mk->rexmit = 0;
	mk->caused_ack = 0;
    }
}

void
TCPMystery::finish(Conn* c)
{
    MyConn* mc = myconn(c);
    if (!mc->_finished) {
	clear(c->stream(0));
	clear(c->stream(1));
	find_true_caused_acks(c->stream(0), c);
	find_true_caused_acks(c->stream(1), c);
	calculate_semirtt(c->stream(0), c);
	calculate_semirtt(c->stream(1), c);
	mc->_finished = true;
    }
}



// Want to develop ack latencies for exactly those packets where the ack
// latency is definitely correct. 

void
TCPMystery::find_true_caused_acks(Stream* datas, Conn* c)
{
    Stream* acks = c->ack_stream(datas);
    Pkt* ackk = acks->pkt_head;

    for (Pkt* k = datas->pkt_head; k && ackk; k = k->next)
	if (k->flags & Pkt::F_NEW) {
	    while (ackk && ackk->timestamp < k->timestamp)
		ackk = ackk->next;
	    while (ackk && SEQ_LT(ackk->max_ack(), k->end_seq))
		ackk = ackk->next;
	    // Avoid if there was a retransmission.
	    if ((k->flags & Pkt::F_NONORDERED) && ackk) {
		for (Pkt* kk = k->next; kk && kk->timestamp < ackk->timestamp; kk = kk->next)
		    if (kk->end_seq == k->end_seq)
			goto next_round;
	    }
	    // Want to avoid ack latencies that might be due to reordering.
	    // This is impossible if the previous ack wasn't a duplicate.
	    if (ackk
		&& ackk->max_ack() == k->end_seq
		&& (ackk->seq == ackk->end_seq || (ackk->flags & (TH_SYN | TH_FIN)))
		&& (!ackk->prev || !ackk->prev->prev
		    || ackk->prev->max_ack() != ackk->prev->prev->max_ack()
		    || ackk->prev->seq != ackk->prev->end_seq)) {
		MyPkt* mk = mypkt(k);
		mk->flags |= MyPkt::F_TRUE_CAUSED_ACK;
		mk->caused_ack = ackk;
	    }
	  next_round: ;
	}
}

void
TCPMystery::calculate_semirtt(Stream* s, Conn* c)
{
    MyStream* ms = mystream(s, c);
    
    ms->semirtt_syn = 0;
    ms->semirtt_min = DBL_MAX;
    ms->semirtt_max = 0;
    ms->semirtt_sum = 0;
    ms->semirtt_sumsq = 0;
    ms->nsemirtt = 0;

    for (Pkt* k = s->pkt_head; k; k = k->next) {
	MyPkt* mk = mypkt(k);
	if (mk->flags & MyPkt::F_TRUE_CAUSED_ACK) {
	    double semirtt = timeval2double(mk->caused_ack->timestamp - k->timestamp);
	    if (k == s->pkt_head)
		ms->semirtt_syn = semirtt;
	    ms->semirtt_min = std::min(ms->semirtt_min, semirtt);
	    ms->semirtt_max = std::max(ms->semirtt_max, semirtt);
	    ms->semirtt_sum += semirtt;
	    ms->semirtt_sumsq += semirtt * semirtt;
	    ms->nsemirtt++;
	}
    }

    if (ms->nsemirtt == 0)
	ms->semirtt_min = 0;
}


void
TCPMystery::mystery_ackcausation_xmltag(FILE* f, TCPCollector::Stream* s, TCPCollector::Conn* c, const String& tagname, void* thunk)
{
    TCPMystery* my = static_cast<TCPMystery*>(thunk);
    my->finish(c);

    fprintf(f, "    <%s", tagname.c_str());
    //if (have_ack_latency)
    //    fprintf(f, " min='%ld.%06ld'", min_ack_latency.tv_sec, min_ack_latency.tv_usec);
    fprintf(f, ">\n");
    
    for (Pkt* k = s->pkt_head; k; k = k->next) {
	MyPkt* mk = my->mypkt(k);
	if (Pkt* ackk = mk->caused_ack) {
	    struct timeval latency = ackk->timestamp - k->timestamp;
	    fprintf(f, "%ld.%06ld %u %ld.%06ld\n", k->timestamp.tv_sec, k->timestamp.tv_usec, ackk->max_ack(), latency.tv_sec, latency.tv_usec);
	}
    }
    
    fprintf(f, "    </%s>\n", tagname.c_str());
}

void
TCPMystery::mystery_semirtt_xmltag(FILE* f, TCPCollector::Stream* s, TCPCollector::Conn* c, const String& tagname, void* thunk)
{
    TCPMystery* my = static_cast<TCPMystery*>(thunk);
    my->finish(c);

    MyStream* ms = my->mystream(s, c);
    if (ms->nsemirtt) {
	if (ms->semirtt_syn)
	    fprintf(f, "    <%s source='syn' value='%g' />\n", tagname.c_str(), ms->semirtt_syn);
	fprintf(f, "    <%s source='min' value='%g' />\n", tagname.c_str(), ms->semirtt_min);
	fprintf(f, "    <%s source='avg' value='%g' n='%d' />\n", tagname.c_str(), ms->semirtt_sum / ms->nsemirtt, ms->nsemirtt);
	fprintf(f, "    <%s source='max' value='%g' />\n", tagname.c_str(), ms->semirtt_max);
	if (ms->nsemirtt > 1)
	    fprintf(f, "    <%s source='var' value='%g' n='%d' />\n", tagname.c_str(), (ms->semirtt_sumsq - (ms->semirtt_sum * ms->semirtt_sum) / ms->nsemirtt) / (ms->nsemirtt - 1), ms->nsemirtt);
    }
}

void
TCPMystery::mystery_rtt_xmltag(FILE* f, TCPCollector::Conn* c, const String& tagname, void* thunk)
{
    TCPMystery* my = static_cast<TCPMystery*>(thunk);
    my->finish(c);

    MyStream* ms0 = my->mystream(c->stream(0), c);
    MyStream* ms1 = my->mystream(c->stream(1), c);
    if (ms0->nsemirtt && ms1->nsemirtt) {
	if (ms0->semirtt_syn && ms1->semirtt_syn)
	    fprintf(f, "  <%s source='syn' value='%g' />\n", tagname.c_str(), ms0->semirtt_syn + ms1->semirtt_syn);
	fprintf(f, "  <%s source='min' value='%g' />\n", tagname.c_str(), ms0->semirtt_min + ms1->semirtt_min);
	fprintf(f, "  <%s source='avg' value='%g' />\n", tagname.c_str(), ms0->semirtt_sum/ms0->nsemirtt + ms1->semirtt_sum/ms1->nsemirtt);
	fprintf(f, "  <%s source='max' value='%g' />\n", tagname.c_str(), ms0->semirtt_max + ms1->semirtt_max);
    }
}


#if 0
void
TCPMystery::find_min_ack_latency(Stream* s, Conn* c)
{
    MyStream* ms = mystream(s, c);
    Pkt* ackk = c->ack_stream(s)->pkt_head;
    ms->have_ack_latency = false;
    for (Pkt* k = s->pkt_head; k && ackk; k = k->next)
	if (k->seq != k->end_seq && !(k->flags & Pkt::F_NONORDERED)) {
	    while (ackk && SEQ_LT(ackk->ack, k->end_seq))
		ackk = ackk->next;
	    if (ackk) {
		timeval diff = ackk->timestamp - k->timestamp;
		if (!ms->have_ack_latency || diff < ms->min_ack_latency) {
		    ms->min_ack_latency = diff;
		    ms->have_ack_latency = true;
		}
	    }
	}
}

void
TCPMystery::find_loss_events(Stream* s, Conn* c)
{
    for (Pkt* k = s->pkt_head; k; k = k->next) {
	
	MyPkt* mk = mypkt(k);
	mk->flags = 0;
	mk->caused_ack = 0;
	mk->rexmit = 0;
	
	// skip pure acks, packets with new data, and network duplicates
	if (k->seq == k->end_seq
	    || (k->flags & (Pkt::F_NEW | Pkt::F_DUPLICATE)))
	    continue;

	// Find the retransmission.
	if (k->flags & Pkt::F_DUPDATA) {
	    for (Pkt* x = k->prev; x; x = x->prev) {
		if (x->seq == x->end_seq)
		    continue;
		if ((x->flags & Pkt::F_NEW) && SEQ_LEQ(x->end_seq, k->seq))
		    break;
		if (x->seq == k->seq && x->end_seq == k->end_seq) {
		    mk->flags |= MyPkt::F_REXMIT | MyPkt::F_FULL_REXMIT;
		    mk->rexmit = x;
		    break;
		} else if ((SEQ_LEQ(x->seq, k->seq) && SEQ_LT(k->seq, x->end_seq))
			   || (SEQ_LT(x->seq, k->end_seq) && SEQ_LEQ(k->end_seq, x->end_seq))) {
		    // partial retransmission. There might be a more relevant
		    // preceding retransmission, so keep searching for one.
		    mk->flags |= MyPkt::F_REXMIT;
		    mk->rexmit = x;
		}
	    }
	    
	} else {
	    // If !F_DUPDATA, then the data in this packet was not seen
	    // earlier in the connection.  But it's not F_NEW, so newer data
	    // was seen previously.  Perhaps we have a retransmission where
	    // the earlier transmission didn't reach the trace point.  Check
	    // that here based on a timing heuristic.
	    int sequence = 1;
	    for (Pkt* x = k->prev; x; x = x->prev, sequence++) {
		if (x->seq == x->end_seq)
		    continue;
		if ((x->flags & Pkt::F_NEW) && SEQ_LEQ(x->end_seq, k->seq)) {
		    // x is the first packet containing new data that is older
		    // than our oldest data.  Assume we have a retransmission
		    // if k->ts >= x->ts + FAC * rtt.  FAC depends on how many
		    // packets have passed.
		    double rtt = timeval2double(c->rtt());
		    double factor = timeval2double(k->timestamp - x->timestamp) / rtt;
		    if (sequence >= 3 ? factor >= 0.4 : factor >= 0.85) {
			mk->flags |= MyPkt::F_REXMIT;
			for (mk->rexmit = x; mk->rexmit->next != k && SEQ_LEQ(mk->rexmit->end_seq, k->seq); mk->rexmit = mk->rexmit->next)
			    /* nada */;
		    }
		}
	    }
	}
	
	// we have identified retransmissions already.
	if (mk->flags & MyPkt::F_REXMIT) {
	    // ignore retransmission of something from an old loss event
	    if (mypkt(mk->rexmit)->event_id == mk->event_id) {
		// new loss event
		mk->flags |= MyPkt::F_EVENT_REXMIT;
		register_loss_event(mk->rexmit, k, conn, parent);
	    }
	} else
	    // if not a retransmission, then a reordering
	    mk->flags |= MyPkt::F_REORDER;
    }
}
#endif



#if 0



//////////////////////////////////////


TCPMystery::MStreamInfo::MStreamInfo()
    : have_ack_latency(false),
      max_live_seq(0), max_loss_seq(0),
      loss_events(0), false_loss_events(0),
      event_id(0), min_ack_latency(make_timeval(0, 0)),
      acked_pkt_hint(0), nreordered(0), nundelivered(0),
      loss_trail(0)
{
    loss.type = NO_LOSS;
}

TCPMystery::MStreamInfo::~MStreamInfo()
{
    while (LossBlock *b = loss_trail) {
	loss_trail = b->next;
	delete b;
    }
}

void
TCPMystery::MStreamInfo::register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *conn, TCPMystery *parent)
{
    // Update the event ID
    event_id++;
    endk->event_id = event_id;

    // Store information about the loss event
    if (loss.type != NO_LOSS) // output any previous loss event
	output_loss(conn, parent);
    if (SEQ_GT(max_ack, endk->seq))
	loss.type = FALSE_LOSS;
    //else if (SEQ_GEQ(endk->end_seq, max_live_seq))
    //    loss.type = POSSIBLE_LOSS;
    else
	loss.type = LOSS;
    loss.time = startk->timestamp;
    loss.data_packetno = startk->data_packetno;
    loss.seq = startk->seq;
    if (SEQ_LT(endk->seq, startk->seq))
	loss.seq = endk->seq;
    loss.end_time = endk->timestamp;
    loss.end_data_packetno = endk->data_packetno;
    loss.top_seq = max_live_seq;

    // We just completed a loss event, so reset max_live_seq and max_loss_seq.
    max_live_seq = endk->end_seq;
    if (SEQ_GT(max_seq, max_loss_seq))
	max_loss_seq = max_seq;
}

void
TCPMystery::MStreamInfo::update_counters(const Pkt *np, const click_tcp *tcph)
{
    // update counters
    total_packets++;
    total_seq += np->end_seq - np->seq;
    if (np->end_seq - np->seq == 0)
	ack_packets++;
    
    // SYN processing
    if (tcph->th_flags & TH_SYN) {
	if (have_syn && syn_seq != np->seq)
	    different_syn = true;
	else {
	    syn_seq = np->seq;
	    have_syn = true;
	}
    }

    // FIN processing
    if (tcph->th_flags & TH_FIN) {
	if (have_fin && fin_seq != np->end_seq - 1)
	    different_fin = true;
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

void
TCPMystery::MStreamInfo::options(Pkt *, const click_tcp *tcph, int transport_length, const ConnInfo *)
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

TCPMystery::Pkt *
TCPMystery::MStreamInfo::find_acked_pkt(const Pkt *ackk, Pkt *search_hint) const
{
    // region of interest is:
    // bounded on the left by a packet whose end_seq < ack, and which is
    // neither a reordering nor a retransmission
    // bounded on the right by a packet whose seq >= ack, and which is not
    // part of a reordered block

    tcp_seq_t ack = ackk->ack;
    
    // move search_hint forward to right edge
    while (search_hint && !(SEQ_GEQ(search_hint->seq, ack)
			    && !(search_hint->flags & Pkt::F_NONORDERED)))
	search_hint = search_hint->next;
    
    // move backwards to left edge
    Pkt *possible = 0;
    int possible_goodness = -1;
    for (Pkt *k = (search_hint ? search_hint->prev : pkt_data_tail);
	 k && (SEQ_GEQ(k->end_seq, ack)
	       || (k->flags & (Pkt::F_REORDER | Pkt::F_REXMIT)))
	     && possible_goodness < 2;
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
	    (!have_ack_latency || ackk->timestamp - k->timestamp >= min_ack_latency)
	    + (k->end_seq == ack);
	// store the best guess so far
	if (goodness > possible_goodness)
	    possible = k, possible_goodness = goodness;
    }

    return possible;
}

#if 0
TCPMystery::Pkt *
TCPMystery::MStreamInfo::find_ack_cause(const Pkt *ackk, Pkt *search_hint) const
{
    // first, find acked packet
    Pkt *result = find_acked_pkt(ackk, search_hint);
    if (!result)
	return 0;

    // move forward from acked packet if this is a duplicate
    if (ackk->prev && ackk->prev->ack == ackk->ack
	&& ackk->seq == ackk->end_seq) {
	// XXX what if reordering happened before the trace point?
	Pkt *r = result->next;
	// move forward to the first nonsequential packet
	while (r && (SEQ_GEQ(ackk->ack, r->seq) || !(r->flags & Pkt::F_DELIVERED)))
	    r = r->next;
	// XXX TCP never acks an ack
	// move forward a number of steps determined by the duplicate count
	for (Pkt *dupctr = ackk->prev->prev;
	     dupctr && r && dupctr->ack == ackk->ack && dupctr->seq == dupctr->end_seq;
	     dupctr = dupctr->prev)
	    for (r = r->next; r && !(r->flags & Pkt::F_DELIVERED); r = r->next)
		/* nada */;
	// XXX duplicates *after* a retransmitted block?
	if (r && ackk->timestamp - r->timestamp >= min_ack_latency)
	    return r;
    }

    // otherwise, we may be in a retransmitted block; check for a recent
    // retransmission
    if ((result->flags & Pkt::F_NONORDERED)
	&& have_ack_latency) {
	struct timeval result_delta = (ackk->timestamp - result->timestamp) - min_ack_latency;
	for (Pkt *k = result->next; k && k->timestamp <= ackk->timestamp; k = k->next)
	    if (SEQ_LT(k->end_seq, ackk->ack)) {
		struct timeval delta = (ackk->timestamp - k->timestamp) - min_ack_latency;
		// XXX apply some fudge factor to this comparison?
		if (delta < result_delta
		    && (delta.tv_sec > 0 || delta.tv_usec > 0)) {
		    result = k;
		    result_delta = delta;
		}
	    }
	return result;
    }

    return result;
}
#endif

#if 0
void
TCPMystery::MStreamInfo::update_cur_min_ack_latency(struct timeval &cur_min_ack_latency, struct timeval &running_min_ack_latency, const Pkt *cur_ack, const Pkt *&ackwindow_begin, const Pkt *&ackwindow_end) const
{
    // find the relevant RTT
    bool refind_min_ack_latency = false;
    if (!ackwindow_begin && !ackwindow_end) {
	refind_min_ack_latency = true;
	ackwindow_begin = cur_ack;
    }
    
    while (ackwindow_begin
	   && (cur_ack->timestamp - ackwindow_begin->timestamp).tv_sec > 5) {
	if (ackwindow_begin->cumack_pkt
	    && ackwindow_begin->timestamp - ackwindow_begin->cumack_pkt->timestamp <= running_min_ack_latency)
	    refind_min_ack_latency = true;
	ackwindow_begin = ackwindow_begin->next;
    }

    if (refind_min_ack_latency) {
	running_min_ack_latency.tv_sec = 10000;	
	ackwindow_end = ackwindow_begin;
    }
    
    while (ackwindow_end
	   && (ackwindow_end->timestamp - cur_ack->timestamp).tv_sec < 5) {
	if (ackwindow_end->cumack_pkt
	    && ackwindow_end->timestamp - ackwindow_end->cumack_pkt->timestamp < running_min_ack_latency)
	    running_min_ack_latency = ackwindow_end->timestamp - ackwindow_end->cumack_pkt->timestamp;
	ackwindow_end = ackwindow_end->next;
    }

    if (running_min_ack_latency.tv_sec >= 10000)
	cur_min_ack_latency = min_ack_latency;
    else
	cur_min_ack_latency = running_min_ack_latency;
}
#endif

TCPMystery::Pkt *
TCPMystery::MStreamInfo::find_ack_cause2(const Pkt *ackk, Pkt *&k_cumack, tcp_seq_t &max_ack) const
{
    // skip undelivered packets and window probes
    // skip packets that have causalities already
    // skip packets with old sequence numbers if this is a new ack
    Pkt *k = k_cumack;

    while (k
	   && (!(k->flags & (Pkt::F_DELIVERED | Pkt::F_WINDOW_PROBE))
	       || k->caused_ack
	       || (SEQ_LT(k->end_seq, ackk->ack) && SEQ_GT(ackk->ack, max_ack))
	       || (SEQ_GT(k->seq, ackk->ack) && SEQ_GT(ackk->ack, max_ack))))
	k = k->next;

    // the packet just before a loss event might not be acknowledged because
    // of duplicate acks
    if (k && k->end_seq == ackk->ack && k->next && !(k->next->flags & Pkt::F_DELIVERED)) {
	int numacks = 1;
	for (Pkt *ackt = ackk->next; ackt && ackt->ack == ackk->ack && ackt->seq == ackt->end_seq; ackt = ackt->next)
	    numacks++;
	int numacksexpected = 0;
	TCPScoreboard sb(ackk->ack);
	for (Pkt *kk = k->next->next; kk && sb.cumack() == ackk->ack && numacksexpected <= numacks; kk = kk->next)
	    if (kk->flags & Pkt::F_DELIVERED) {
		sb.add(kk->seq, kk->end_seq);
		numacksexpected++;
	    }
	//click_chatter("%u ack: %u vs. %u", ackk->ack, numacks, numacksexpected);
	if (numacksexpected > numacks)
	    k = k->next;
    }
    
    // Only set k_cumack to the new value if acks were not reordered.
    if (!k || !(ackk->flags & Pkt::F_ACK_NONORDERED))
	k_cumack = k;

    // From this point on, we are shifting over packets that might, indeed,
    // cause ack latencies later, so don't change the stable k_cumack hint.

    // If this ack is greater than the last cumulative ack, then it probably
    // isn't in response to a packet with greater sequence number
    if (k && ackk->prev && SEQ_GT(ackk->ack, ackk->prev->ack)
	&& SEQ_GT(k->end_seq, ackk->ack))
	k = k->next;
    
    // Handle reordering: skip packets that are in a hole.
    if (k && ackk->ack == k->seq && !(k->flags & Pkt::F_WINDOW_PROBE)) {
	// Don't shift forward if the next ack acks this packet (that would be
	// an impossible reordering situation)
	Pkt *next_ackk;
	for (next_ackk = ackk->next; next_ackk && next_ackk->ack == ackk->ack; next_ackk = next_ackk->next)
	    /* nada */;
	if (next_ackk && next_ackk->ack == k->end_seq) // Impossible!
	    k = 0;
	else
	    k = k->next;
    }

    // Shift over impossible packets again
    while (k && (!(k->flags & (Pkt::F_DELIVERED | Pkt::F_WINDOW_PROBE))
		 || k->caused_ack))
	k = k->next;

    // If the ack causality is unusually long, check for a later match
    if (k && ackk->timestamp - k->timestamp >= 2 * min_ack_latency) {
	Pkt *new_k_cumack = k->next;
	tcp_seq_t new_max_ack = max_ack;
	if (SEQ_GT(k->end_seq, new_max_ack))
	    new_max_ack = k->end_seq;
	Pkt *new_k = find_ack_cause2(ackk, new_k_cumack, new_max_ack);
	// Ignore later matches that don't significantly change the delay
	if (new_k && ackk->timestamp - new_k->timestamp <= 0.5 * (ackk->timestamp - k->timestamp) && SEQ_LEQ(new_k->end_seq, k->end_seq))
	    k = new_k;
    }
    
    if (k && ackk->timestamp - k->timestamp >= 0.8 * min_ack_latency) {
	if (SEQ_GT(k->end_seq, max_ack) && !(ackk->flags & Pkt::F_ACK_REORDER))
	    max_ack = k->end_seq;
	// If the new match started a retransmission section, change cumack
	if (k && (k->flags & Pkt::F_EVENT_REXMIT) && !(ackk->flags & Pkt::F_ACK_NONORDERED)) {
	    for (Pkt *kk = k_cumack; kk != k; kk = kk->next)
		if ((kk->flags & Pkt::F_DELIVERED) && SEQ_GT(kk->end_seq, max_ack))
		    max_ack = kk->end_seq;
	    k_cumack = k;
	}
	return k;
    } else
	return 0;
}

bool
TCPMystery::MStreamInfo::mark_delivered(const Pkt *ackk, Pkt *&k_cumack, Pkt *&k_time, tcp_seq_t prev_ackno, int prev_ndupack) const
{
    //click_chatter("mark_delivered at %{timeval}: %u  CA %{timeval}:%u  TH %{timeval}:%u  %{timeval}", &ackk->timestamp, ackk->ack, (k_cumack ? &k_cumack->timestamp : 0), (k_cumack ? k_cumack->end_seq : 0), (k_time ? &k_time->timestamp : 0), (k_time ? k_time->end_seq : 0), &min_ack_latency);
    
    // update current RTT
    struct timeval cur_min_ack_latency = min_ack_latency;
    
    // move k_time forward
    while (k_time && ackk->timestamp - k_time->timestamp >= 0.8 * cur_min_ack_latency)
	k_time = k_time->next;

    // move k_time backward if this followed a string of dupacks
    if (prev_ndupack && k_time) {
	Pkt *k = k_time;
	while (k->prev && SEQ_GT(k->prev->seq, prev_ackno) && k != k_cumack)
	    k = k->prev;
	if (k != k_cumack)
	    k_time = k;
    }

    // go over previous packets, marking them as delivered
    if (!k_time || k_time != k_cumack) {
	Pkt *k_time_hint = k_time;
#define ACK_JUMP_SECTION 1
#if ACK_JUMP_SECTION
	bool ack_jump_section = (ackk->prev && ackk->prev->ack != ackk->ack);
	uint32_t ack_jump_end_seq = ackk->ack;
#endif
	for (Pkt *k = (k_time ? k_time->prev : pkt_tail); k && k != k_cumack; k = k->prev) {
	    if (SEQ_LEQ(k->end_seq, ackk->ack) && k->seq != k->end_seq) {
		// can we find an already-received packet covering these
		// sequence numbers?
		for (Pkt *kk = k->next; kk != k_time_hint; kk = kk->next)
		    if ((kk->flags & Pkt::F_DELIVERED)
			&& SEQ_LEQ(kk->seq, k->seq)
			&& SEQ_GEQ(kk->end_seq, k->end_seq))
			goto not_delivered;
		
		// otherwise, this puppy was delivered
		k->flags |= Pkt::F_DELIVERED;

#if ACK_JUMP_SECTION
		// if the ack number jumped inside a reordered section,
		// previous packets were delivered too
		if (ack_jump_section
		    && (k->flags & Pkt::F_NONORDERED)
		    && SEQ_LEQ(k->end_seq, ack_jump_end_seq)
		    && SEQ_GT(k->seq, ackk->prev->ack)) {
		    // except ignore this heuristic in cases that look like
		    // delayed acks
		    if (!(k->prev && ackk->prev->prev
			  && SEQ_LEQ(k->prev->seq, ackk->prev->ack)
			  && SEQ_GEQ(k->end_seq, ackk->ack)
			  && ackk->prev->prev->ack != ackk->prev->ack
			  && (!ackk->next || ackk->next->ack != ackk->ack))) {
			k_time_hint = k;
			ack_jump_end_seq = k->seq;
		    }
		}
#endif

	      not_delivered: ;
	    }

#if ACK_JUMP_SECTION
	    // we have left the ack jump section if we've encountered a packet
	    // starting at or after the previous ack
	    if (ack_jump_section && SEQ_LEQ(k->seq, ackk->prev->ack))
		ack_jump_section = false;
#endif
	}
    }
    
    // finally, move k_cumack forward
    if (!k_cumack)
	k_cumack = pkt_head;
    // must be SEQ_LT
    // 3.Feb.2004 - Add k_cumack != k_time check to avoid bad behavior on
    // weird traces where acks mistakenly precede data (NLANR)
    while (k_cumack && k_cumack != k_time && SEQ_LT(k_cumack->end_seq, ackk->ack))
	k_cumack = k_cumack->next;
    return k_cumack;
}

void
TCPMystery::MStreamInfo::unfinish()
{
    for (Pkt *k = pkt_head; k; k = k->next) {
	k->flags &= ~Pkt::F_DELIVERED;
	k->caused_ack = 0;
    }
}

void
TCPMystery::MStreamInfo::finish(ConnInfo *conn, TCPMystery *)
{
    // calculate delivered packets
    {
	Pkt *k_cumack = 0, *k_time = pkt_head;
	tcp_seq_t last_ack = 0;
	int last_ndupack = 0;
	for (Pkt *ackk = conn->stream(1-direction)->pkt_head; ackk; ackk = ackk->next)
	    if (ackk->ack == last_ack)
		last_ndupack++;
	    else if (SEQ_GT(ackk->ack, last_ack)) {
		if (!mark_delivered(ackk, k_cumack, k_time, last_ack, last_ndupack))
		    break;
		last_ack = ackk->ack;
		last_ndupack = 0;
	    }
    }

    // calculate ack causality
    {
	const StreamInfo *acks = conn->stream(!direction);
	Pkt *hint = pkt_head;
	tcp_seq_t max_ack = 0;
	for (Pkt *ack = acks->pkt_head; ack; ack = ack->next)
	    if (ack->seq == ack->end_seq) {
		//Pkt *old_hint = hint;
		//tcp_seq_t max_ack2 = max_ack;
		if (Pkt *k = find_ack_cause2(ack, hint, max_ack))
		    k->caused_ack = ack;
	    }
    }
}

bool
TCPMystery::LossInfo::unparse(StringAccum &sa, const StreamInfo *cstr, const ConnInfo *conn, bool include_aggregate, bool absolute_time, bool absolute_seq) const
{
    if (type == NO_LOSS)
	return false;

    // figure out loss type, count loss
    if (type == LOSS)
	sa << "loss ";
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
TCPMystery::MStreamInfo::output_loss(ConnInfo *conn, TCPMystery *cf)
{
    if (loss.type == NO_LOSS)
	return;

    // figure out loss type, count loss
    if (loss.type == LOSS)
	loss_events++;
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

TCPMystery::MConnInfo::MConnInfo()
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

timeval
TCPMystery::MConnInfo::rtt() const
{
    if (_stream[0].have_ack_latency && _stream[1].have_ack_latency)
	return _stream[0].min_ack_latency + _stream[1].min_ack_latency;
    else if (_stream[0].have_ack_latency)
	return _stream[0].min_ack_latency;
    else if (_stream[1].have_ack_latency)
	return _stream[1].min_ack_latency;
    else
	return make_timeval(10000, 0);
}


void
TCPMystery::LossInfo::unparse_xml(StringAccum &sa, const String &tagname) const
{
    if (type != NO_LOSS)
	sa << "    <" << tagname
	   << (type == LOSS ? " type='loss'" : " type='floss'")
	   << " time='" << time << "' seq='" << seq << "' endtime='"
	   << end_time << "' lastseq='" << top_seq << "' dpacketno='"
	   << data_packetno << "' enddpacketno='" << end_data_packetno
	   << "' />\n";
}

void
TCPMystery::LossBlock::write_xml(FILE *f, const String &tagname) const
{
    if (next)
	next->write_xml(f);
    StringAccum sa(n * 80);
    for (int i = 0; i < n; i++)
	loss[i].unparse_xml(sa, tagname);
    fwrite(sa.data(), 1, sa.length(), f);
}

void
TCPMystery::mystery_loss_xmltag(FILE *f, TCPCollector::StreamInfo &stream, TCPCollector::ConnInfo &conn, const String &tagname, void *thunk)
{
    TCPMystery *my = static_cast<TCPMystery *>(thunk);
    MConnInfo *mconn = my->mconn(&conn);
    mconn->finish(conn, my);
    MStreamInfo &mstream = mconn->stream(stream.direction);
    if (mstream.loss_trail)
	mstream.loss_trail->write_xml(f, tagname);
}



void
TCPMystery::mystery_reordered_xmltag(FILE *f, TCPCollector::StreamInfo &stream, TCPCollector::ConnInfo &conn, const String &tagname, void *thunk)
{
    TCPMystery *my = static_cast<TCPMystery *>(thunk);
    MConnInfo *mconn = my->mconn(&conn);
    mconn->finish(conn, my);
    MStreamInfo &mstream = mconn->stream(stream.direction);

    fprintf(f, "    <%s count='%u'", tagname.c_str(), mstream.nreordered);
    if (have_ack_latency)
	fprintf(f, " min='%ld.%06ld'", min_ack_latency.tv_sec, min_ack_latency.tv_usec);
    if (mstream.nreordered == 0) {
	fprintf(f, " />\n");
	return;
    }
    
    fprintf(f, ">\n");
    
    for (Pkt *k = stream.pkt_head; k; k = k->next) {
	MPkt *mk = my->mpkt(k);
	MPkt *next_mk = (k->next ? my->mpkt(k->next) : 0);
	if ((mk->flags & MPkt::F_REORDER)
	    || (mk->caused_ack && next_mk && next_mk->caused_ack
		&& mk->caused_ack->timestamp > next_mk->caused_ack->timestamp))
	    fprintf(f, "%ld.%06ld %u\n", k->timestamp.tv_sec, k->timestamp.tv_usec, k->end_seq);
    }
    
    fprintf(f, "    </%s>\n", tagname.c_str());
}

void
TCPMystery::mystery_undelivered_xmltag(FILE *f, TCPCollector::StreamInfo &stream, TCPCollector::ConnInfo &conn, const String &tagname, void *thunk)
{
    TCPMystery *my = static_cast<TCPMystery *>(thunk);
    MConnInfo *mconn = my->mconn(&conn);
    mconn->finish(conn, my);
    MStreamInfo &mstream = mconn->stream(stream.direction);

    fprintf(f, "    <%s count='%u'", tagname.c_str(), mstream.nundelivered);
    if (have_ack_latency)
	fprintf(f, " min='%ld.%06ld'", min_ack_latency.tv_sec, min_ack_latency.tv_usec);
    if (mstream.nundelivered == 0) {
	fprintf(f, " />\n");
	return;
    }
    
    fprintf(f, ">\n");
    
    for (Pkt *k = stream.pkt_head; k; k = k->next) {
	MPkt *mk = my->mpkt(k);
	if (!(mk->flags & MPkt::F_DELIVERED) && k->seq != k->end_seq)
	    fprintf(f, "%ld.%06ld %u\n", k->timestamp.tv_sec, k->timestamp.tv_usec, k->end_seq);
    }
    
    fprintf(f, "    </%s>\n", tagname.c_str());
}


void
TCPMystery::MStreamInfo::write_xml(ConnInfo *conn, FILE *f) const
{
    int nreordered = 0, nundelivered = 0;
    for (Pkt *k = pkt_head; k; k = k->next)
	if (k->seq == k->end_seq)
	    /* not interesting */;
	else if (!(k->flags & Pkt::F_DELIVERED))
	    nundelivered++;
	else if ((k->flags & Pkt::F_REORDER)
		 || (k->caused_ack && k->next && k->next->caused_ack
		     && k->caused_ack->timestamp > k->next->caused_ack->timestamp))
	    nreordered++;
}

void
TCPMystery::MConnInfo::finish(TCPMystery *cf)
{
    if (!(_finished && _clean)) {
	if (_finished) {
	    _stream[0].unfinish();
	    _stream[1].unfinish();
	}
	_stream[0].finish(this, cf);
	_stream[1].finish(this, cf);
	_finished = _clean = true;
    }
}

void
TCPMystery::MConnInfo::kill(TCPMystery *cf)
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

	if (_stream[0].have_ack_latency && _stream[1].have_ack_latency) {
	    timeval min_rtt = _stream[0].min_ack_latency + _stream[1].min_ack_latency;
	    fprintf(f, "  <rtt source='minacklatency' value='%ld.%06ld' />\n", min_rtt.tv_sec, min_rtt.tv_usec);
	}
	
	_stream[0].write_xml(this, f, cf->write_flags());
	_stream[1].write_xml(this, f, cf->write_flags());
	
	fprintf(f, "</flow>\n");
    }
    cf->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    cf->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    delete this;
}

TCPMystery::Pkt *
TCPMystery::MConnInfo::create_pkt(const Packet *p, TCPMystery *parent)
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

    // check for timestamp confusion
    struct timeval timestamp = p->timestamp_anno() - _init_time;
    if (stream.pkt_tail && timestamp < stream.pkt_tail->timestamp) {
	stream.time_confusion = true;
	return 0;
    }

    // introduce a Pkt
    if (Pkt *np = parent->new_pkt()) {
	const click_ip *iph = p->ip_header();

	// set fields appropriately
	np->data_packetno = stream.total_packets - stream.ack_packets;
	np->seq = ntohl(tcph->th_seq) - stream.init_seq;
	np->end_seq = np->seq + calculate_seqlen(iph, tcph);
	np->ack = ntohl(tcph->th_ack) - ack_stream.init_seq;
	if (!(tcph->th_flags & TH_ACK))
	    np->ack = 0;
	np->ip_id = (parent->_ip_id ? iph->ip_id : 0);
	np->timestamp = p->timestamp_anno() - _init_time;
	np->packetno_anno = PACKET_NUMBER_ANNO(p, 0);
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
TCPMystery::MConnInfo::post_update_state(const Packet *p, Pkt *k, TCPMystery *cf)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);

    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);

    // update acknowledgment information for other half-connection
    StreamInfo &ack_stream = _stream[!direction];
    if (tcph->th_flags & TH_ACK) {
	if (SEQ_GT(k->ack, ack_stream.max_ack))
	    ack_stream.max_ack = k->ack;
	else if (k->ack != ack_stream.max_ack) {
	    k->flags |= Pkt::F_ACK_NONORDERED;
	    for (Pkt *prev = k->prev; prev && SEQ_LT(k->ack, prev->ack); prev = prev->prev)
		prev->flags |= Pkt::F_ACK_NONORDERED | Pkt::F_ACK_REORDER;
	}
	
	// find acked packet
	if (!k->prev || k->ack != k->prev->ack)
	    if (Pkt *acked_pkt = ack_stream.find_acked_pkt(k, ack_stream.acked_pkt_hint)) {
		ack_stream.acked_pkt_hint = acked_pkt;
		struct timeval latency = k->timestamp - acked_pkt->timestamp;
		if (!ack_stream.have_ack_latency || latency < ack_stream.min_ack_latency) {
		    ack_stream.have_ack_latency = true;
		    ack_stream.min_ack_latency = latency;
		}
	}
	    
	// check whether this acknowledges something in the last loss event;
	// if so, we should output the loss event
	if (ack_stream.loss.type != NO_LOSS
	    && SEQ_GT(k->ack, ack_stream.loss.seq)) {
	    // check for a false loss event: we don't believe the ack
	    // could have seen the retransmitted packet yet
	    if (ack_stream.have_ack_latency
		&& k->timestamp - ack_stream.loss.end_time < 0.6 * ack_stream.min_ack_latency)
		ack_stream.loss.type = FALSE_LOSS;
	    ack_stream.output_loss(this, cf);
	}
    }

    // did packet fill receive window? was it a window probe?
    if (k->end_seq == ack_stream.end_rcv_window) {
	k->flags |= Pkt::F_FILLS_RCV_WINDOW;
	_stream[direction].filled_rcv_window = true;
    } else if (k->seq == ack_stream.end_rcv_window
	       && k->prev) {	// first packet never a window probe
	k->flags |= Pkt::F_WINDOW_PROBE;
	_stream[direction].sent_window_probe = true;
    }
}

void
TCPMystery::MConnInfo::handle_packet(const Packet *p, TCPMystery *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    _clean = false;
    
    // update timestamp and sequence number offsets at beginning of connection
    if (Pkt *k = create_pkt(p, parent)) {
	int direction = (PAINT_ANNO(p) & 1);
	_stream[direction].categorize(k, this, parent);
	_stream[direction].update_counters(k, p->tcp_header());
	_stream[direction].options(k, p->tcp_header(), p->transport_length(), this);

	// update counters, maximum sequence numbers, and so forth
	post_update_state(p, k, parent);
    }
}


// CALCULATEFLOWS PROPER

TCPMystery::TCPMystery()
    : Element(1, 1), _tipfd(0), _tipsd(0), _traceinfo_file(0), _filepos_h(0),
      _free_pkt(0), _packet_source(0)
{
    MOD_INC_USE_COUNT;
}

TCPMystery::~TCPMystery()
{
    MOD_DEC_USE_COUNT;
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
    delete _filepos_h;
}

void
TCPMystery::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int 
TCPMystery::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *af_element = 0, *tipfd_element = 0, *tipsd_element = 0;
    bool acklatency = false, ackcausality = false, ip_id = true, full_rcv_window = false, undelivered = false, window_probe = false, packets = false, reordered = false;
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
		    "ACKCAUSALITY", cpBool, "output ack causality XML?", &ackcausality,
		    "FULLRCVWINDOW", cpBool, "output receive window fillers XML?", &full_rcv_window,
		    "WINDOWPROBE", cpBool, "output window probes XML?", &window_probe,
		    "UNDELIVERED", cpBool, "output undelivered packets XML?", &undelivered,
		    "REORDERED", cpBool, "output reordered packets XML?", &reordered,
		    "PACKET", cpBool, "output packet XML?", &packets,
		    "IP_ID", cpBool, "use IP ID to distinguish duplicates?", &ip_id,
		    cpEnd) < 0)
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
    _write_flags = (acklatency ? WR_ACKLATENCY : 0)
	| (ackcausality ? WR_ACKCAUSALITY : 0)
	| (full_rcv_window ? WR_FULLRCVWND : 0)
	| (window_probe ? WR_WINDOWPROBE : 0)
	| (undelivered ? WR_UNDELIVERED : 0)
	| (packets ? WR_PACKETS : 0)
	| (reordered ? WR_REORDERED : 0);
    return 0;
}

int
TCPMystery::initialize(ErrorHandler *errh)
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
TCPMystery::cleanup(CleanupStage)
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

Packet *
TCPMystery::simple_action(Packet *p)
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


enum { H_CLEAR, H_SAVE };

int
TCPMystery::save(int, uint32_t aggregate, int direction, const String &filename, ErrorHandler *errh)
{
    ConnInfo *loss = _conn_map.find(aggregate);
    if (!loss)
	return errh->error("no '%u' aggregate", aggregate);
    
    FILE *f;
    if (!filename || filename == "-")
	f = stdout;
    else if (!(f = fopen(filename.c_str(), "w")))
	return errh->error("%s: %s", filename.c_str(), strerror(errno));

    loss->finish(this);

    for (Pkt *k = loss->stream(direction)->pkt_head; k; k = k->next)
	if (!(k->flags & Pkt::F_DELIVERED))
	    fprintf(f, "%u\n", k->packetno_anno);

    if (f != stdout)
	fclose(f);
    return 0;
}

int
TCPMystery::write_handler(const String &s, Element *e, void *thunk, ErrorHandler *errh)
{
    TCPMystery *cf = static_cast<TCPMystery *>(e);
    switch ((intptr_t)thunk) {
      case H_CLEAR:
	for (ConnMap::iterator i = cf->_conn_map.begin(); i; i++)
	    i.value()->kill(cf);
	cf->_conn_map.clear();
	return 0;
      case H_SAVE: {
	  String what, filename;
	  uint32_t aggregate;
	  if (cp_va_space_parse(s, cf, errh,
				cpWord, "data type", &what,
				cpUnsigned, "aggregate number", &aggregate,
				cpFilename, "save file", &filename, cpEnd) < 0)
	      return -1;
	  if (what == "undelivered_packetno")
	      return cf->save(SAVE_UNDELIVERED_PACKETNO, aggregate, 0, filename, errh);
	  else
	      return errh->error("no such data type '%#s'", what.c_str());
      }
      default:
	return -1;
    }
}

void
TCPMystery::add_handlers()
{
    add_write_handler("clear", write_handler, (void *)H_CLEAR);
    add_write_handler("save", write_handler, (void *)H_SAVE);
}
#endif


ELEMENT_REQUIRES(userlevel TCPScoreboard)
EXPORT_ELEMENT(TCPMystery)
#include <click/bighashmap.cc>
#include <click/dequeue.cc>
CLICK_ENDDECLS
