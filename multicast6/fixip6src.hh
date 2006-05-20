#ifndef CLICK_FIXIP6SRC_HH
#define CLICK_FIXIP6SRC_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
CLICK_DECLS

/*
 * =c
 * FixIP6Src(IPADDR)
 * =s IPv6
 * sets IP source field if requested by annotation
 * =d
 *
 * Expects an IP packet as input. It
 * changes its IP source address field to IPADDR and recomputes the checksum.
 * It is used by MLD and PIM to set the correct outgoing interface IP6 address.
 *
 * =a MLD, PIM */

class FixIP6Src : public Element {
 

public:
  FixIP6Src();
  ~FixIP6Src();
  
  IP6Address fixip6addr;
  //  IP6Address src_ip;
  
  const char *class_name() const		{ return "FixIP6Src"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }
  int configure(Vector<String> &, ErrorHandler *);
  void printIP6(IP6Address);
  WritablePacket *fix_it(Packet *p_in);
  Packet *simple_action(Packet *);
  
};

CLICK_ENDDECLS
#endif
