#ifndef IP6PIMFORWARDINGTABLE_HH
#define IP6PIMFORWARDINGTABLE_HH
CLICK_DECLS
#include <click/element.hh>
#include <click/ip6address.hh>

/*
=c
IP6PIMForwardingTable()

=s
IPv6 Multicast

=d
Takes care of arriving multicast traffic. Streams are duplicated and forwarded to neighbouring routers which are connected to Rendezvous Point or Source Path Trees.

=a
IPv6MulticastTable, MLD, IP6PIMControl, IP6PIM, IP6MC_EtherEncap, IP6FixPIMSource
*/

#define MODE unsigned char
#define INCLUDEMODE 0x00
#define EXCLUDEMODE 0x01
#define MODE_NOT_SET 0x02

class IP6PIMForwardingTable : public Element {

  
 public:

  IP6PIMForwardingTable();
  ~IP6PIMForwardingTable();
  int configure(Vector<String> &, ErrorHandler *);

  const char *class_name() const	{ return "IP6PIMForwardingTable"; }
  const char *port_count() const	{ return "1/1"; }
  const char *processing() const	{ return "h/h"; }

  /*
   * groupsource holds a group address and all allowed sources
   *
   * a pair of group / source Address is also known as "channel"
   *
   */  
  struct groupsource {
	IP6Address neighbor;
	IP6Address group;
	IP6Address source;
  };


  /*
   * pimtable holds the IP address of an interface and all source/group entries
   *
   */
  struct piminterface {
    IP6Address interface;                           // interface 
	IP6Address neighbor;                           // neighbor interface
	Vector<groupsource> groupsources; 
  };

  Vector<piminterface> piminterfaces;
  click_in6_addr get_upstreamneighbor(IP6Address);
  bool addinterface(IP6Address, IP6Address);
  bool addgroup(IP6Address, IP6Address, IP6Address, IP6Address);
  bool delgroup(IP6Address);
  bool delgroup(IP6Address, IP6Address, IP6Address, IP6Address);
  bool printgroups();
  void push(int, Packet *);
  bool getPIMreceivers(IP6Address, IP6Address);
};

CLICK_ENDDECLS
#endif
