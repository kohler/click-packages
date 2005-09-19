#ifndef DHCPCLIENTLEASEQUEUE_HH
#define DHCPCLIENTLEASEQUEUE_HH

#include <click/ipaddress.hh>
#include <click/element.hh>

/*
 * =c
 * DHCPOfferMsgQueue(read_handler)
 *
 * =s
 * Stores DHCPOffer packets in a queue ordered by the duration of the leases.

 * =d 
 *
 * Stores DHCPOffer Packets in a queue ordered by the duration of the
 * DHO_DHCP_LEASE_TIME option field. When a down stream element
 * (DHCPClient) pulls from this queue, it will invoke the down
 * stream's registered read handler to see if there's a requested
 * IP. If so, this element tries to find the match within its
 * queue. If a match is not found, it will return a DHCP_OFFER packet
 * with the longest lease. Furthermore, once an offer is chosen, the
 * rest of the queued-up packets will be discarded.
 *
 * =e
 * client :: DHCPClient(00:11:22:33:44);
 * client[2] -> queue :: DHCPOfferMsgQueue(client.client_ip_read);
 * queue -> [1] client;
 *
 * =a
 * DHCPClient
 *
 */
class HandlerCall;

class DHCPOfferMsgQueue : public Element
{
public:
  DHCPOfferMsgQueue();
  ~DHCPOfferMsgQueue();
  
  const char *class_name() const	{ return "DHCPOfferMsgQueue"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *processing() const	{ return "h/l"; }
  
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  
  void push(int port, Packet*);
  Packet* pull(int port);
  
  
  
private:
  class QueueNode
  {
  public:
    uint32_t _lease_time;
    IPAddress _ipAddr;
    QueueNode *_next;
    Packet *_p;

    QueueNode(uint32_t t, uint32_t ipAddr)
	: _lease_time(t), _ipAddr(ipAddr)
      {
	
      }
  };
  
  QueueNode *_requested_lease;
  QueueNode *_head;
  
  HandlerCall *_client_read_handler_call;

  void enqueue(Packet *p);
  Packet* dequeue();
  Packet* remove(const IPAddress &ip_addr);
};

#endif
