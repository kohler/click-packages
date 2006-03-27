#ifndef MLD_HH
#define MLD_HH
#include "ip6multicasttable.hh"
#include "ip6protocoldefinitions.hh"
#include <click/timer.hh>
#include <click/element.hh>

/*
=c
MLD(IP6MulticastTable)

=s
IPv6 Multicast

=d
Handles most of the MLD protocol (RFC2710, RFC3810). Was tested against Microsoft Windows XP and Linux Vanilla Kernel 2.6.9.
MLD join/leave messages are also processed. Queries are MLDv2 only.
This element checks whether an arriving MLD message is valid (checksum) and takes appropriate actions. 

It manages the databank of listeners kept in the IP6MulticastTable element.

=e
mct::IP6MulticastTable("pimctl");
mcc :: Classifier(6/11 24/ff, // UDP Multicast traffic
 6/00 40/3a 42/0502, // Hop-by-hop header, ICMP, MLD router alert
 6/67, // PIM
 -);
...mcc[1] -> MLD("mct") -> rt;

=a
IP6MulticastTable, IP6PIM, IP6PIMControl, IP6PIMForwardingTable, IP6MC_EtherEncap, IP6FixPIMSource
*/

class MLD : public Element { public:
  
  MLD();
  ~MLD();

  IP6MulticastTable *MCastTable;
  
  const char *class_name() const	{ return "MLD"; }
  const char *port_count() const  	{ return "1/2"; }
  const char *processing() const	{ return "h/hh"; }


  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  Packet *simple_action(Packet *);
  

  // this does not really belong here but i do not want to extend existing click elements
  struct hopbyhopheader {
	unsigned char type;
	unsigned char length;
	unsigned short parameter;
	unsigned int empty;
  };

private:

  void generalquery();
  void run_timer(Timer *);
  bool change_to_include_mode(IP6Address, IP6Address, unsigned short, unsigned short);
  bool change_to_exclude_mode(IP6Address, IP6Address, unsigned short, unsigned short);
  bool allow_new_sources(IP6Address, IP6Address, unsigned short, unsigned short);  
  bool block_old_sources(IP6Address, IP6Address, unsigned short, unsigned short);
  bool has_embedded_rp(IP6Address group);
  IP6Address extract_rp(IP6Address group);

  /* if there is another mld router on the same network the router with the lowest IP address 
   * keeps being active, the other one is disabled
   * if activequerier is false, this router does not generate MLD queries 
   */

  bool querierstate; 
  
  mldv2report *report;
  mldv1message *v1report;
  mldv2querie *v2query;
  static const int QUERY_INTERVAL = 125000;
  static const int QUERY_RESPONSE_INTERVAL = 10000;
  //  static const int QUERY_INTERVAL = 125000;
  Timer _timer;
};

#endif
