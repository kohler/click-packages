#ifndef DHCPICMPENCAP_HH
#define DHCPICMPENCAP_HH

#include "dhcp_common.hh"
#include <click/element.hh>
class HandlerCall;

class DHCP_ICMP_Encap : public Element
{
public:
  DHCP_ICMP_Encap();
  ~DHCP_ICMP_Encap();
  
  const char *class_name() const { return "DHCP_ICMP_Encap"; }
  const char *processing() const { return AGNOSTIC; }
  
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  Packet *simple_action(Packet *);

private:
  HandlerCall *_src_ip_h;
  HandlerCall *_dst_ip_h;
};

#endif
