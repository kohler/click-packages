#ifndef DHCPCLASSIFIER_HH
#define DHCPCLASSIFIER_HH

#include <click/element.hh>
#include <click/hashtable.hh>

/*
 * =c 
 * DHCPClassifier([ discover | offer | request | deline | ack | nack | release | inform ], -)
 * =s DHCP
 * Classifies dhcp packets by DHCP_MESSAGE_TYPE
 *
 * =d 
 * Classifies dhcp packets according to the DHCP_MESSAGE_TYPE option field.
 * 
 * =e
 * class::DHCPClassifier(discover, request, -);
 * 
 * class[0] -> Print(DISCOVER) -> Discard; 
 * class[1] -> Print(REQUEST) -> Discard;
 * class[2] -> Print(all others) -> Discard;
 *
 * =a
 * CheckDHCPMsg
 */

//class IPAddress;
//class EtherAddress;
//class dhcpMessage;
//class DHCPInfo;

class DHCPClassifier : public Element {

public:
  DHCPClassifier();
  ~DHCPClassifier();
  
  const char *class_name() const	{ return "DHCPClassifier"; }
  const char *port_count() const	{ return "1/-"; }
  const char *processing() const	{ return PUSH; }
  
  int configure(Vector<String> &, ErrorHandler *);
  virtual void push(int port, Packet *p);
  
private:
  HashTable<uint32_t, int> _dhcp_msg_to_outport_map;
  
};

#endif
