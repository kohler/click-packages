#ifndef IP6MULTICASTTABLE_HH
#define IP6MULTICASTTABLE_HH

#include "ip6pimcontrol.hh"
#include <click/element.hh>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
#include "debug.hh"


/*
=c
IP6MulticastTable(IP6PIMControl)

=s
IPv6 Multicast

=d
Includes data structures to store addresses of receivers of multicast streams (IPv6).
Each multicast group entry can hold information about senders and receivers.
The data structures is based upon STL containers.

=e
mct::IP6MulticastTable("pimctl");
mcc :: Classifier(6/11 24/ff, // UDP Multicast traffic
 6/00 40/3a 42/0502, // Hop-by-hop header, ICMP, MLD router alert
 6/67, // PIM
 -);
mcc[0] -> mct;
mct[0] -> rt;

=a
MLD, IP6PIM, IP6PIMControl, IP6PIMForwardingTable, IP6MC_EtherEncap, IP6FixPIMSource
*/

CLICK_DECLS

#define MODE unsigned char
#define INCLUDEMODE 0x00
#define EXCLUDEMODE 0x01
#define MODE_NOT_SET 0x02

class IP6MulticastTable : public Element {

  
 public:

  IP6MulticastTable();
  ~IP6MulticastTable();

  IP6PIMControl* pPim;

  //set pim-enable, disable
  
  bool use_pim;
  
  const char *class_name() const	{ return "IP6MulticastTable"; }
  const char *port_count() const	{ return "1/2"; }
  const char *processing() const	{ return "h/hh"; }



  struct receiver {
	click_in6_addr receiver;
	MODE mode;
	Vector<click_in6_addr> sources; // for SSM = Source Specific Multicast the senders IPs are needed
  };

  //  receiver *new_receiver;

  struct MulticastGroup {
	click_in6_addr group; // group address
	Vector<receiver> receivers; // a group can be joined by one or more receivers
  };

  MulticastGroup *gp;

  Vector<MulticastGroup> multicastgroups;

  int configure(Vector<String> &, ErrorHandler *);
  void printIP6(IP6Address);
  bool printreceiver(Vector<MulticastGroup>::iterator);
  bool addgroup(IP6Address);
  bool joingroup(IP6Address, IP6Address);
  unsigned char get_receiver_mode(IP6Address, IP6Address);
  bool set_receiver_mode(IP6Address, IP6Address, MODE);
  bool addsource(IP6Address, IP6Address, IP6Address);
  bool delsource(IP6Address, IP6Address, IP6Address);
  bool leavegroup(IP6Address, IP6Address);
  bool printgroups(bool);
  void push(int, Packet *);
  bool getMLDreceivers(IP6Address, IP6Address);
};

CLICK_ENDDECLS
#endif
