#ifndef IP6MC_ETHERENCAP_HH
#define IP6MC_ETHERENCAP_HH
#include <click/element.hh>
#include <clicknet/ether.h>
CLICK_DECLS

/*
=c

IP6MC_EtherEncap(ETHERTYPE, SRC)

=s
IPv4 Multicast

=d

Encapsulates each packet in the Ethernet header specified by its arguments and the packet's Multicast IP destination address.
ETHERTYPE should be in host order.

=e

Encapsulate packets in an Ethernet header with type
ETHERTYPE_IP (0x0800) and source address 1:1:1:1:1:1

  EtherEncap(0x0800, 1:1:1:1:1:1)
  
the destination MAC address is derived from the packets IP destination address like suggested in RFC1112.

=n

For unicast IP packets you probably want to use ARPQuerier or EtherEncap instead.

=a

ARPQuerier, EtherEncap, PIM, IGMP
*/

class IP6mc_EtherEncap : public Element { public:
  
  IP6mc_EtherEncap();
  ~IP6mc_EtherEncap();

  const char *class_name() const	{ return "IP6mc_EtherEncap"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *processing() const	{ return AGNOSTIC; }
  
  int configure(Vector<String> &, ErrorHandler *);

  Packet *smaction(Packet *);
  void push(int, Packet *);
  Packet *pull(int);
  
 private:

  click_ether _ethh;

};

CLICK_ENDDECLS
#endif
