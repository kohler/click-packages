#ifndef IP6PIM_HH
#define IP6PIM_HH
#include "ip6pimcontrol.hh"
#include "ip6multicasttable.hh"
#include "ip6pimforwardingtable.hh"
#include "ip6protocoldefinitions.hh"
#include <click/timer.hh>
#include <click/ip6address.hh>
#include <click/element.hh>

/*
=c
IP6PIM(IP6PIMForwardingTable, IP6PIMControl, Interfaceaddress)

=s
IPv6 Multicast

=d
Handles PIM messages. Arriving PIM messages are checked and processed.
A working Click multicast configuration must have a PIM element attached to each
incoming interface.
This element manages the IP6PIMForwardingTable.

It manages the databank of PIM receivers kept in the IP6PIMForwardingTable element.

Takes the interface IP address it is connected to as last argument. 

=e
pim1::IP6PIM("pimft", "pimctl", 3ffe:1001:7d0:2::3);

=a
IP6MulticastTable, MLD, IP6PIMControl, IP6PIMForwardingTable, IP6MC_EtherEncap, IP6FixPIMSource
*/

class IP6PIM : public Element { public:
  
  IP6PIM();
  ~IP6PIM();

  IP6PIMForwardingTable *PIMTable;
  IP6PIMControl* PIMSpt;
  IP6MulticastTable* MulticastTable;
  
  const char *class_name() const	{ return "IP6PIM"; }
  const char *port_count() const  	{ return "1/2"; }
  const char *processing() const	{ return "h/hh"; }


  int configure(Vector<String> &, ErrorHandler *);


  void push(int port, Packet *);
  IP6Address extract_rp(IP6Address);



private:
  click_in6_addr interface;
  unsigned short calculate_checksum(const unsigned char*, int);
};

#endif
