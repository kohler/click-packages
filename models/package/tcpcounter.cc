#include <click/config.h>
#include "tcpcounter.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <packet_anno.hh>
#include <click/click_tcp.h>

TCPCounter::TCPCounter()
    : Element(1,1)
{
    MOD_INC_USE_COUNT;
}

TCPCounter::~TCPCounter()
{
    MOD_DEC_USE_COUNT;
}

int
TCPCounter::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    return 0;
}

int
TCPCounter::initialize(ErrorHandler *errh)
{
    return 0;
}

Packet *
TCPCounter::simple_action(Packet *p)
{
    const click_ip *iph = p->ip_header();

    IPAddress dstaddr = IPAddress(iph->ip_dst);
 
    IPAddress srcaddr = IPAddress(iph->ip_src);

    const click_tcp *tcph = p->tcp_header();

    //NOTE: the TCPconnection is only one directional here.
    TCPConnection conn = TCPConnection(srcaddr,tcph->th_sport,dstaddr,tcph->th_dport);

    TCPConnectionCounter *c = _hashed_tcpcounters.findp(conn);
    if (!c) {
	if (tcph->th_flags == TH_SYN) {
	    TCPConnectionCounter newc = TCPConnectionCounter(p->timestamp_anno(),(unsigned int) tcph->th_seq);
	    _hashed_tcpcounters.insert(conn,newc);
	}
    }else {
	//check for possible packet losses
	unsigned int curr_seq = tcph->th_seq;
	if (curr_seq < c->seq_no) {
	    c->total_pkts_lost++;
	}else if (curr_seq > c->seq_no){
	    //just set a big to indicate if re-ordering happens (if so, the packet loss count is not accurate)
	    if (curr_seq != (c->seq_no + 1) ) {
		c->reordered = true;
	    }
	    c->seq_no = curr_seq;
	}
    }

    
    if (tcph->th_flags == TH_FIN) {
	//get rid of the current connection
	c->end_time = p->timestamp_anno();
	print_connection(conn,c);
	_hashed_tcpcounters.remove(conn);
    }
    return p;
}

void
TCPCounter::print_connection(TCPCounter::TCPConnection &conn, TCPCounter::TCPConnectionCounter *c)
{
    //srcip dstip sport dport starttime endtime bytes_transferred pkts_lost reordered
    printf("%s %s %d %d %ld.%ld %ld.%ld %d %d %d\n",
	    conn.srcip.s().cc(), conn.dstip.s().cc(), conn.srcport,conn.dstport,
	    (c->start_time).tv_sec,(c->start_time).tv_usec,
	    c->end_time.tv_sec,c->end_time.tv_usec,
	    c->seq_no - c->start_seqno,
	    c->total_pkts_lost,
	    c->reordered?1:0);
}

EXPORT_ELEMENT(TCPCounter);

#include <click/bighashmap.cc>
#if EXPLICIT_TEMPLATE_INSTANCES
template class BigHashMap<TCPCounter::TCPConnection, TCPCounter::TCPConnectionCounter>
#endif
