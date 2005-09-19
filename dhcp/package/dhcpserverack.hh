#ifndef DHCPSERVERACKNAK_HH
#define DHCPSERVERACKNAK_HH

#include <click/element.hh>
#include "dhcpserverleases.hh"

/*
 * =c
 * DHCPServerACKorNAK( DHCPServerLeases )
 *
 * =s 
 * 
 * Handles incoming DHCP_REQUEST. Sends out DHCP_ACK or DHCP_NAK
 * accordingly.
 *
 * =d 
 * 
 * 
 * =e
 *
 * =a
 * DHCPServerLeases, DHCPServerACKorNACK, DHCPServerOffer
 *
 *
 */

class DHCPServerACKorNAK : public Element
{
public:
  DHCPServerACKorNAK();
  ~DHCPServerACKorNAK();
  
  const char *class_name() const { return "DHCPServerACKorNAK"; }
  const char *port_count() const { return "1/1-2"; }
  const char *processing() const { return PUSH; }
  
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  virtual void push(int port, Packet *p);
  Packet *make_ack_packet(Packet *p, DHCPServerLeases::Lease *lease);
  Packet *make_nak_packet(Packet *p, DHCPServerLeases::Lease *lease);
  Packet* drop(Packet *p);
  
private:
  DHCPServerLeases *_serverLeases;
};
#endif
