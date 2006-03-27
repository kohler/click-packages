#ifndef IP6PIM_CONTROL_HH
#define IP6PIM_CONTROL_HH
#include "ip6pimforwardingtable.hh"
#include "ip6protocoldefinitions.hh"
#include <click/timer.hh>
#include <click/element.hh>

/*
=c
IP6PIMControl(IP6PIMForwardingTable)

=s
IPv6 Multicast

=d
Handles the PIM protocol, i.e. generation of Hello-messages and detection of connected PIM routers.
This management information is needed for PIMForwardingTable.

=e
IP6PIMControl("pimft") -> rt;
=a
IP6MulticastTable, IP6PIM, MLD, IP6PIMForwardingTable, IP6MC_EtherEncap, IP6FixPIMSource

*/


class IP6PIMControl : public Element { public:
  
  IP6PIMControl();
  ~IP6PIMControl();

  bool source_connected;

  IP6PIMForwardingTable *PIMTable;
  
  const char *class_name() const	{ return "IP6PIMControl"; }
  const char *port_count() const  	{ return "0/1"; }
  const char *processing() const	{ return "h/h"; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void generatejoinprune(IP6Address, IP6Address, bool);
  void run_timer(Timer *);
  void generate_hello();
  Timer _timer;
  bool noPIMreceivers(IP6Address, IP6Address);
  IP6Address extract_rp(IP6Address);
};

#endif
