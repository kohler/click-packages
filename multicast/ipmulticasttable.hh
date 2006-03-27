#ifndef IPV4MULTICASTTABLE_HH
#define IPV4MULTICASTTABLE_HH
CLICK_DECLS
#include <click/element.hh>
#include "pimcontrol.hh"


/*
=c

IPMulticastTable(PIMControl)

=s
IPv4 Multicast

=d
Includes data structures to store addresses of receivers of multicast streams (IPv4).
Each multicast group entry can hold information about senders and receivers.
The data structures is based upon STL containers.

=e
mct::IPMulticastTable("pimctl");
mcc::IPClassifier(224.0.0.0/4 and ip proto udp, ip proto igmp, -);
mcc[0] -> mct;
mct[0] -> rt;

=a
IGMP, PIM, PIMControl, PIMForwardingTable, IPMulticastEtherEncap, FixPIMSource
*/

#define MODE unsigned char
#define INCLUDEMODE 0x00
#define EXCLUDEMODE 0x01
#define MODE_NOT_SET 0x02

class IPMulticastTable : public Element {

  
 public:

  IPMulticastTable();
  ~IPMulticastTable();

  const char *class_name() const	{ return "IPMulticastTable"; }
  const char *port_count() const	{ return "1/2"; }
  const char *processing() const	{ return "h/hh"; }

  struct receiver {
	IPAddress receiver;
	MODE mode;
	Vector<IPAddress> sources; // for SSM = Source Specific Multicast the senders IPs are needed
  };

  struct MulticastGroup {
	unsigned int interface_id;
	IPAddress group; // group address
	Vector<receiver> receivers; // a group can be joined by one or more receivers
  };

  MulticastGroup *gp;

  Vector<MulticastGroup> multicastgroups;
  Vector<bool> interfaces;

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  bool printreceiver(Vector<MulticastGroup>::iterator);
  bool addgroup(IPAddress);
  bool joingroup(IPAddress, IPAddress, unsigned int);
  unsigned char get_receiver_mode(IPAddress, IPAddress);
  bool set_receiver_mode(IPAddress, IPAddress, MODE);
  bool addsource(IPAddress, IPAddress, IPAddress);
  bool delsource(IPAddress, IPAddress, IPAddress);
  bool leavegroup(IPAddress, IPAddress);
  bool printgroups(bool);
  void push(int, Packet *);
  bool getIGMPreceivers(IPAddress, IPAddress);

private:
  bool pimenable;
  unsigned int no_of_interfaces;
  PIMControl* pPim;
};

CLICK_ENDDECLS
#endif
