#ifndef PIM_HH
#define PIM_HH
#include "pimcontrol.hh"
#include "pimforwardingtable.hh"
#include "protocoldefinitions.hh"
#include "ipmulticasttable.hh"
#include <click/timer.hh>
#include <click/element.hh>


/*
=c
PIM(IPMulticastTable, PIMForwardingTable, PIMControl, Interfaceaddress)

=s
IP Multicast

=d
Handles PIM messages. Arriving PIM messages are checked and processed.
A working Click multicast configuration must have a PIM element attached to each
incoming interface.
This element manages the PIMForwardingTable.

It manages the databank of PIM receivers kept in the PIMForwardingTable element.

Takes the interface IP address it is connected to as last argument. 

=e
pim1::PIM("pimft", "pimctl", 192.168.30.6);
... Paint(0) -> Strip(14) -> CheckIPHeader(INTERFACES 192.168.30.6/32 224.0.0.0/4) -> pim1;

=a
IPMulticastTable, IGMP, PIMControl, PIMForwardingTable, IPMulticastEtherEncap, FixPIMSource
*/
class PIM : public Element { public:
  
  PIM();
  ~PIM();

  PIMForwardingTable *PIMTable;
  PIMControl* PIMSpt;
  IPMulticastTable* MulticastTable;
  
  const char *class_name() const	{ return "PIM"; }
  const char *port_count() const  	{ return "1/2"; }
  const char *processing() const	{ return "h/hh"; }


  int configure(Vector<String> &, ErrorHandler *);

  void push(int port, Packet *);

private:
  IPAddress interface;
  unsigned short calculate_checksum(const unsigned char*, int);
};

#endif
