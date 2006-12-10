// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>

#include "dhcpunicastencap.hh"

#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/handlercall.hh>
CLICK_DECLS

DHCPUnicastEncap::DHCPUnicastEncap()
    :_src_ip_h(0),
     _dst_ip_h(0)
{
}

DHCPUnicastEncap::~DHCPUnicastEncap()
{
  delete _src_ip_h;
  delete _dst_ip_h;
}

int 
DHCPUnicastEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if( cp_va_parse( conf, this, errh,
		   cpReadHandlerCall, "src ip read", &_src_ip_h,
		   cpReadHandlerCall, "dst ip read", &_dst_ip_h,
		   cpEnd ) < 0 )
  {
    return -1;
  }
  return 0;
}

int 
DHCPUnicastEncap::initialize(ErrorHandler *errh)
{
  if( _src_ip_h->initialize_read(this, errh) < 0 )
    return -1;
  if( _dst_ip_h->initialize_read(this, errh) < 0 )
    return -1; 
  
  return 0;
}


Packet *
DHCPUnicastEncap::simple_action(Packet *p)
{
  String src_str = _src_ip_h->call_read();
  String dst_str = _dst_ip_h->call_read();
  click_ip *ip = (click_ip *)(p->data());
  click_udp *udp = (click_udp*)(ip + 1);

  click_chatter("[e] og_src: %s", IPAddress(ip->ip_src).unparse().data());
  click_chatter("[e] og_dst: %s", IPAddress(ip->ip_dst).unparse().data());

  ip->ip_src = IPAddress(src_str).in_addr();
  ip->ip_dst = IPAddress(dst_str).in_addr();

  click_chatter("[e] src: %s", src_str.data());
  click_chatter("[e] dst: %s", dst_str.data());

  ip->ip_sum = 0;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
  click_chatter("[e] HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED");
  if (_aligned)
    ip->ip_sum = ip_fast_csum((unsigned char *)ip, sizeof(click_ip) >> 2);
  else
    ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
#elif HAVE_FAST_CHECKSUM
  click_chatter("[e] HAVE_FAST_CHECKSUM");
  ip->ip_sum = ip_fast_csum((unsigned char *)ip, sizeof(click_ip) >> 2);
#else
  click_chatter("[e] else");
  ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
#endif
  
  p->set_dst_ip_anno(IPAddress(ip->ip_dst));
  p->set_ip_header(ip, sizeof(click_ip));

  udp->uh_sum = 0;
  uint16_t len = p->length() - sizeof(click_ip);
  // assume that we are doing check sum
  unsigned csum = click_in_cksum((unsigned char *)udp, len);
  udp->uh_sum = click_in_cksum_pseudohdr(csum, ip, len);
  
  return p;
}

EXPORT_ELEMENT(DHCPUnicastEncap)
