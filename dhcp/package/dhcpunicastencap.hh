#ifndef DHCPUNICASTENCAP_HH
#define DHCPUNICASTENCAP_HH

#include "dhcp_common.hh"
#include <click/element.hh>
class HandlerCall;

/*
 * =c
 * DHCPUnicastEncap(src_ip_read_handler, dst_ip_read_handler)
 *
 * =s 
 * Changes the ip_src and ip_dst of an outgoing packet, according to
 * the read_handlers output.
 *
 * =d
 * This element should be connected right after UDPIPEncap. Since
 * currently the arguments, such as src_ip, dest_up, are passed into
 * UDIPEncap statically, the purpose of this element is to provide a
 * way to be able to change dest_up and src_ip at runtime. For
 * example, this is helpful when a client gets a different lease from
 * a different server. After a period of time, the client would like
 * to renew its current lease. This element helps to modify the ip_src
 * and ip_dst fields accordingly.
 *
 * =e
 * client[1] -> udp_encap::UDPIPEncap( 111.11.11.11, 68, 111,22,33,4, 67 )
 *           -> DHCPUnicastEncap(client.client_ip_read, client.server_ip_read)
 *           -> EtherEncap( 0x0800, 52:54:00:E5:33:17 , ff:ff:ff:ff:ff:ff) 
 *           -> Queue(1000)->ToDevice(eth0);
 * =a
 * DHCPClient
 */

class DHCPUnicastEncap : public Element
{
public:
  DHCPUnicastEncap();
  ~DHCPUnicastEncap();

  const char *class_name() const { return "DHCPUnicastEncap"; }
  const char *processing() const { return AGNOSTIC; }
  
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);

  Packet *simple_action(Packet *);
  
private:
  HandlerCall *_src_ip_h;
  HandlerCall *_dst_ip_h;
};

#endif
