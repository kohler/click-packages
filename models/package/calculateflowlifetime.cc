#include <config.h>
#include <click/config.h>

#include "calculatevariance.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <packet_anno.hh>

CalculateFlowLifetime::CalculateFlowLifetime()
    : Element(1,1)
{
    MOD_INC_USE_COUNT;
}

CalculateFlowLifetime::~CalculateFlowLifetime()
{
    MOD_DEC_USE_COUNT;
}

int
CalculateFlowLifetime::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    return 0;
}

int
CalculateFlowLifetime::initialize(ErrorHandler *)
{
    reset();
    return 0;
}

Packet *
CalculateFlowLifetime::simple_action(Packet *p)
{
    int dst_ip;

    const click_ip *iph = p->ip_header();
    IPAddress dstaddr = IPAddress(iph->ip_dst);
    dst_ip = (uint32_t) ntohl(dstaddr.addr());

    CalculateFlowLifetime::CounterEntry *ent = _hashed_counters.findp(dst_ip);
}
