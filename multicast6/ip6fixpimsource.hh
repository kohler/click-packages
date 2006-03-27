#ifndef IP6CLICK_FIXPIMSOURCE_HH
#define IP6CLICK_FIXPIMSOURCE_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip6.h>
#include <click/ipaddress.hh>
#include "ip6pimforwardingtable.hh"

/*
=c
IP6FixPIMSource(PIMForwardingTable)

=s
IPv6 Multicast

=d
Adds upstream interface IP to PIM join/prune messages and calculates the checksum.
=e
...-> FixPIMSource(3ffe:1001:7d0:2::3, "pimft")

=e
IP6FixPIMSource("pimft") -> rt;
=a
IP6MulticastTable, IP6PIM, MLD, IP6PIMForwardingTable, IP6MC_EtherEncap, IP6PIMControl

*/

class IP6FixPIMSource : public Element {
 

public:
  IP6FixPIMSource();
  ~IP6FixPIMSource();

  IP6PIMForwardingTable *PIMTable;
  
  int configure(Vector<String> &, ErrorHandler *);


  const char *class_name() const		{ return "IP6FixPIMSource"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }

  WritablePacket *fixpimsource(Packet *);
  Packet *simple_action(Packet *);

  
private:

  click_in6_addr interfaceaddr;

  // 0, 4 byte
  struct PIMMessage {
	uint8_t ver_type;
	uint8_t reserved;
	uint16_t checksum;
	uint8_t addr_family;
	uint8_t encoding_type;
        uint8_t uaddr[16];
  };




};

CLICK_ENDDECLS
#endif
