#ifndef DHCPSERVEROFFER_HH
#define DHCPSERVEROFFER_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "leasetable.hh"
#include "dhcp_common.hh"

/*
 * =c
 * DHCPServerOffer(LEASES)
 *
 * =s DHCP
 *
 * Handles incoming DHCP_DISCOVER. Sends out DHCP_OFFER if appropriate.
 *
 * =d 
 * 
 * DHPServerOffer has at most 2 input and at most 2 output
 * ports. Input port 0 is used for handling DHCP_DISCOVER
 * packets. Input port 1 is used for handling ICMP ECHO REPLY
 * packets. DHCP_OFFER packets go out from output port 0. ICMP_PING
 * packets go out from output port 1. The user can simply disconnect
 * the ICMP related connections to disable pinging prior to sending the
 * DHCP_OFFER packet. 
 *
 * =e
 *
 * ...
 * ->ipclass:: IPClassifier(icmp type echo-reply, -)
 * 
 * ipclass[0] -> [1]serverOffer::DHCPServerOffer(server);
 *
 * ipclass[1] -> CheckDHCPMsg(request) -> class :: DHCPClassifier( discover, - );
 *
 * class[0]-> [0]serverOffer
 * 
 * serverOffer[0] -> .... //udp_encap->eth_encap->...->ToDevice
 * serverOffer[1] -> ....// icmpEncap -> DHCPICMPEncap ->...->ToDevice
 *
 * =a
 * DHCPServerLeases, DHCPServerACKorNACK, DHCPServerRelease
 *
 */

class DHCPServerOffer : public Element
{
public:
  DHCPServerOffer();
  ~DHCPServerOffer();

  const char *class_name() const { return "DHCPServerOffer"; }
  const char *port_count() const { return "1-2/1-2"; }
  const char *processing() const { return PUSH; }

  int configure(Vector<String> &conf, ErrorHandler *errh);
  virtual void push(int port, Packet *p);
  Packet* make_offer_packet(dhcpMessage *discover_msg, Lease *lease);

  void add_handlers();
  

private:
  DHCPLeaseTable *_leases;
};

#endif
