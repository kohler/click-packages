#ifndef PIMFORWARDINGTABLE_HH
#define PIMFORWARDINGTABLE_HH
CLICK_DECLS
#include <click/element.hh>

/*
=c
PIMForwardingTable()

=s
IPv4 Multicast

=d
Takes care of arriving multicast traffic. Streams are duplicated and forwarded to neighbouring routers which are connected to Rendezvous Point or Source Path Trees.

=a
IPMulticastTable, IGMP, PIMControl, PIM, IPMulticastEtherEncap, FixPIMSource
*/

#define MODE unsigned char
#define INCLUDEMODE 0x00
#define EXCLUDEMODE 0x01
#define MODE_NOT_SET 0x02

class PIMForwardingTable : public Element {

  
 public:

  PIMForwardingTable();
  ~PIMForwardingTable();
  int configure(Vector<String> &, ErrorHandler *);

  const char *class_name() const	{ return "PIMForwardingTable"; }
  const char *port_count() const	{ return "1/1"; }
  const char *processing() const	{ return "h/h"; }

  /*
   * groupsource holds a group address and all allowed sources
   *
   * a pair of group / source Address is also known as "channel"
   *
   */  
  struct groupsource {
	IPAddress neighbor;
	IPAddress group;
	IPAddress source;
  };


  /*
   * pimtable holds the IP address of an interface and all source/group entries
   *
   */
  struct piminterface {
    IPAddress interface;                           // interface
	IPAddress neighbor;
	Vector<groupsource> groupsources; 
  };

  Vector<piminterface> piminterfaces;

  bool addinterface(IPAddress, IPAddress);
  bool addgroup(IPAddress, IPAddress, IPAddress, IPAddress);
  bool delgroup(IPAddress);
  bool delgroup(IPAddress, IPAddress, IPAddress, IPAddress);
  bool printgroups();
  void push(int, Packet *);
  uint32_t get_upstreamneighbor(IPAddress);
  bool getPIMreceivers(IPAddress, IPAddress);
};

CLICK_ENDDECLS
#endif
