// -*- mode: c++; c-basic-offset: 4 -*-
#include <config.h>
#include <click/config.h>

#include "flowtoaddress.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <click/click_ip.h>
#include <click/click_tcp.h>
#include <click/click_udp.h>
#include <click/packet_anno.hh>

FlowToAddress::FlowToAddress()
    : Element(1, 1)
{
    MOD_INC_USE_COUNT;
}

FlowToAddress::~FlowToAddress()
{
    MOD_DEC_USE_COUNT;
}

int
FlowToAddress::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    _bidi = false;
    _ports = true;
    return cp_va_parse(conf, this, errh,
		       cpKeywords,
		       "BIDI", cpBool, "bidirectional?", &_bidi,
		       "PORTS", cpBool, "use ports?", &_ports,
		       0);
}

int
FlowToAddress::initialize(ErrorHandler *)
{
    _next = IPAddress(htonl(1));
    return 0;
}

Packet *
FlowToAddress::simple_action(Packet *p)
{
    const click_ip *p_ip = p->ip_header();
    if (!p_ip || (_ports && p_ip->ip_p != IP_PROTO_TCP && p_ip->ip_p != IP_PROTO_UDP)) {
	p->kill();
	return 0;
    }

    WritablePacket *q = p->uniqueify();
    if (!q)
	return 0;

    click_ip *iph = q->ip_header();

    IPFlowID flow;
    if (_ports)
	flow = IPFlowID(q);
    else
	flow = IPFlowID(iph->ip_src, 0, iph->ip_dst, 0);

    Map &m = (iph->ip_p == IP_PROTO_TCP ? _tcp_map : _udp_map);
    
    IPAddress addr = m.find(flow);
    if (!addr && _bidi)
	addr = m.find(flow.rev());
    if (!addr) {
	addr = _next;
	m.insert(flow, addr);
	_next = IPAddress(htonl(ntohl(_next.addr()) + 1));
    }

    iph->ip_dst = addr;
    return q;
}

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(FlowToAddress)

#include <click/bighashmap.cc>
