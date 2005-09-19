#ifndef DHCPSERVEROFF_HH
#define DHCPSERVEROFF_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "dhcpserverleases.hh"

/*
 * =c
 * DHCPServerOffer( DHCPServerLeases )
 *
 * =s 
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
 * serverOffer[1] -> ....// icmpEncap -> DHCP_ICMP_ENncap ->...->ToDevice
 *
 * =a
 * DHCPServerLeases, DHCPServerACKorNACK, DHCPServerRelease
 *
 */

class DHCPServerOffer : public Element
{
private:
  typedef struct _lease_node
  {
    DHCPServerLeases::Lease *v;
    Packet *dm;
    struct _lease_node *next;
    ~_lease_node(){
      dm->kill();
    }
  }LeaseNode;

  class LeaseFIFOQueue{
  public:
    LeaseFIFOQueue();
    ~LeaseFIFOQueue();
    void enqueue(DHCPServerLeases::Lease *lease, Packet *p);
    DHCPServerOffer::LeaseNode * dequeue();
    
  private:
    LeaseNode *_lease_fifo_head;
    LeaseNode *_lease_fifo_tail;
  };

public:
  DHCPServerOffer();
  ~DHCPServerOffer();

  const char *class_name() const { return "DHCPServerOffer"; }
  const char *port_count() const { return "1-2/1-2"; }
  const char *processing() const { return PUSH; }

  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  virtual void push(int port, Packet *p);
  void run_timer();
  Packet* make_offer_packet(LeaseNode *lease);

  void add_handlers();
  
  const DHCPServerLeases* getServerLeases() const;
  const IPAddress &get_curr_icmp_dst_ipAddr() const;

private:
  DHCPServerLeases *_serverLeases;
  Timer _send_offer_timer;
  IPAddress _curr_icmp_dst_ipAddr;

  ///// begin lease FIFO queue related stuff /////
      
  
  ///// end lease FIFO queue related stuff /////

  LeaseFIFOQueue _lease_fifo_queue;
};

#endif
