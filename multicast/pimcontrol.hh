#ifndef PIM_CONTROL_HH
#define PIM_CONTROL_HH
#include "pimforwardingtable.hh"
#include "protocoldefinitions.hh"
#include <click/timer.hh>
#include <click/element.hh>

/*
=c
PIMControl(PIMForwardingTable)

=s
IPv4 Multicast

=d
Handles the PIM protocol, i.e. generation of Hello-messages and detection of connected PIM routers.
This management information is needed for PIMForwardingTable.

=e
PIMControl("pimft") -> rt;
=a
IPMulticastTable, PIM, IGMP, PIMForwardingTable, IPMulticastEtherEncap, FixPIMSource

*/

class PIMControl : public Element { public:
  
  PIMControl();
  ~PIMControl();

  bool source_connected;
  PIMForwardingTable *PIMTable;
  
  const char *class_name() const	{ return "PIMControl"; }
  const char *port_count() const  	{ return "0/2"; }
  const char *processing() const	{ return "h/hh"; }



  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void join(IPAddress, IPAddress);
  void prune(IPAddress, IPAddress);
  void generatejoin(IPAddress, IPAddress, bool);
  void run_timer(Timer *);
  void generate_hello();
  bool noPIMreceivers(IPAddress, IPAddress);
  bool noIGMPreceivers(IPAddress, IPAddress);
  Timer _timer;

};

#endif
