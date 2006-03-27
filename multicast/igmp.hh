#ifndef IGMP_HH
#define IGMP_HH
#include "protocoldefinitions.hh"
#include "ipmulticasttable.hh"
#include <click/timer.hh>
#include <click/element.hh>

/*
=c
IGMP(IPMulticastTable)

=s
IPv4 Multicast

=d
Handles most of the IGMPv3 protocol (RFC3376). Was tested against Microsoft Windows XP and Linux Vanilla Kernel 2.6.9.
IGMPv1 and IGMPv2 join/leave messages are also processed. Queries are IGMPv3 only.
This element checks whether an arriving IGMP message is valid (checksum) and takes appropriate actions. 

It manages the databank of listeners kept in the IPMulticastTable element.

=e
mct::MulticastTable("pimctl");

mcc::IPClassifier(224.0.0.0/4 and ip proto udp, ip proto igmp, -);

...mcc[1] -> IGMP("mct") -> rt;

=a
IPMulticastTable, PIM, PIMControl, PIMForwardingTable, IPMulticastEtherEncap, FixPIMSource
*/



class IGMP : public Element { public:
  
  IGMP();
  ~IGMP();

  IPMulticastTable *MCastTable;
  
  const char *class_name() const	{ return "IGMP"; }
  const char *port_count() const  	{ return "1/2"; }
  const char *processing() const	{ return "h/hh"; }


  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  Packet *simple_action(Packet *);

private:

  void query(IPAddress, IPAddress);
  //  void generalquery();
  void run_timer(Timer *);
  bool change_to_include_mode(IPAddress, IPAddress, unsigned short, unsigned short, unsigned int);
  bool change_to_exclude_mode(IPAddress, IPAddress, unsigned short, unsigned short, unsigned int);
  bool allow_new_sources(IPAddress, IPAddress, unsigned short, unsigned short, unsigned int);  
  bool block_old_sources(IPAddress, IPAddress, unsigned short, unsigned short);

  /* if there is another igmp router on the same network the router with the lowest IP address 
   * keeps being active, the other one is disabled
   * if activequerier is false, this router does not generate IGMP queries 
   *
   * this is not working yet
   */

  bool activequerier; 


  igmpv1andv2message *v1andv2message;
  igmpv3report *v3report;

  static const int INTERVAL = 4000; // RFC says 125000;
  Timer _igmptimer;
};

#endif
