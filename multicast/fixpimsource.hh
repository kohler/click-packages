#ifndef CLICK_FIXPIMSOURCE_HH
#define CLICK_FIXPIMSOURCE_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>
#include <click/ipaddress.hh>
#include "pimforwardingtable.hh"
CLICK_DECLS

/*
=c
FixPIMSource(outgoing interface's IP address, PIMForwardingTable)

=s
IPv4 Multicast

=d
Adds upstream interface IP to PIM join/prune messages and calculates the checksum.
=e
...-> FixPIMSource(172.20.12.2, "pimft")

=a
IPMulticastTable, PIM, IGMP, PIMForwardingTable, IPMulticastEtherEncap 

*/

class FixPIMSource : public Element {
 

public:
  FixPIMSource();
  ~FixPIMSource();
 
  PIMForwardingTable *PIMTable;
 
  int configure(Vector<String> &, ErrorHandler *);


  const char *class_name() const		{ return "FixPIMSource"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }

  WritablePacket *fixpimsource(Packet *);
  Packet *simple_action(Packet *);

  
private:

  IPAddress interfaceaddr;

  // 0, 4 byte
  struct PIMMessage {
	uint8_t ver_type;
	uint8_t reserved;
	uint16_t checksum;
	uint8_t addr_family;
	uint8_t encoding_type;
	uint16_t uaddr[2];
  };




};

CLICK_ENDDECLS
#endif
