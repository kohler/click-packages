#ifndef DHCPCLASSIFIER_HH
#define DHCPCLASSIFIER_HH

#include <click/element.hh>

#include <click/bighashmap.hh>

/*
 * =c 
 * DHCPClassifier([ discover | offer | request | deline | ack | nack | release | inform ], -)
 * =s
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
  const char *processing() const	{ return PUSH; }
  
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  virtual void push(int port, Packet *p);
  
private:
  HashMap<uint32_t, int> _dhcp_msg_to_outport_map;
  
};

#endif
