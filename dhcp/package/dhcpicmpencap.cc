// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>

#include "dhcpicmpencap.hh"

#include <click/error.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/icmp.h>
#include <click/handlercall.hh>
CLICK_DECLS

DHCP_ICMP_Encap::DHCP_ICMP_Encap()
    :_src_ip_h(0),
     _dst_ip_h(0)
{
}

DHCP_ICMP_Encap::~DHCP_ICMP_Encap()
{
    delete _src_ip_h;
    delete _dst_ip_h;
}

int
DHCP_ICMP_Encap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    HandlerCall srch, dsth;
    if (Args(conf, this, errh)
	.read_mp("SRC_CALL", HandlerCallArg(HandlerCall::readable), srch)
	.read_mp("DST_CALL", HandlerCallArg(HandlerCall::readable), dsth)
	.complete() < 0)
	return -1;
    _src_ip_h = new HandlerCall(srch);
    _dst_ip_h = new HandlerCall(dsth);
    return 0;
}

int
DHCP_ICMP_Encap::initialize(ErrorHandler *errh)
{
  if( _src_ip_h->initialize_read(this, errh) < 0 )
    return -1;
  if( _dst_ip_h->initialize_read(this, errh) < 0 )
    return -1;

  return 0;
}

Packet *
DHCP_ICMP_Encap::simple_action(Packet *p)
{
  String src_str = _src_ip_h->call_read();
  String dst_str = _dst_ip_h->call_read();
  click_ip *ip = (click_ip *)(p->data());
  
  ip->ip_src = IPAddress(src_str).in_addr();
  ip->ip_dst = IPAddress(dst_str).in_addr();
  
  click_icmp_echo *icmp = (struct click_icmp_echo *) (ip + 1);
  
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
  if (_aligned)
    ip->ip_sum = ip_fast_csum((unsigned char *)ip, sizeof(click_ip) >> 2);
  else
    ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
#elif HAVE_FAST_CHECKSUM
  ip->ip_sum = ip_fast_csum((unsigned char *)ip, sizeof(click_ip) >> 2);
#else
  ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
#endif
  icmp->icmp_cksum = click_in_cksum((const unsigned char *)icmp, p->length() - sizeof(click_ip));
  
  return p;
}

EXPORT_ELEMENT(DHCP_ICMP_Encap)
