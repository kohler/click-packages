// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
// include your own config.h if appropriate
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "dhcpoffermsgqueue.hh"
#include "dhcpoptionutil.hh"

#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/handlercall.hh>
CLICK_DECLS

DHCPOfferMsgQueue::DHCPOfferMsgQueue()
    : _requested_lease(0),
      _head(0),
      _client_read_handler_call(0)
{
  set_ninputs(1);
  add_output();
}

DHCPOfferMsgQueue::~DHCPOfferMsgQueue()
{
  delete _client_read_handler_call;
}

int 
DHCPOfferMsgQueue::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if( cp_va_parse(conf, this, errh,
		  cpReadHandlerCall, "queue read", &_client_read_handler_call,
		  cpEnd) < 0 )
  {
    return -1;
  }
  return 0;
}

int 
DHCPOfferMsgQueue::initialize(ErrorHandler *errh)
{
  if(_client_read_handler_call->initialize_read(this, errh) < 0)
    return -1;
  
  return 0;
}

void 
DHCPOfferMsgQueue::push(int, Packet* p)
{
  click_chatter("[q] DHCPOFFER");
  enqueue(p);
}

Packet* 
DHCPOfferMsgQueue::pull(int)
{
  String s = _client_read_handler_call->call_read();
  click_chatter("[q] _client_read_handler_call: %x", _client_read_handler_call);
  click_chatter("[q] from client_read_handler : %s", s.data());
		
  IPAddress req_ip(s);
  Packet *p = remove(req_ip);
  
  if(p == NULL)
  {
    p = dequeue();
  }

  Packet *discard_p = dequeue();
  while(discard_p != NULL)
  {
    discard_p->kill();
    discard_p = dequeue();
  }
  return p;
}

void 
DHCPOfferMsgQueue::enqueue(Packet *p)
{
  dhcpMessage *dm =
    (dhcpMessage*) (p->data()+sizeof(click_udp)+sizeof(click_ip));
  int optionFieldSize;
  uint32_t lease_duration;
  uint32_t offered_ip;

  unsigned char *lease_duration_ptr =
    DHCPOptionUtil::getOption(dm->options, DHO_DHCP_LEASE_TIME, &optionFieldSize);
  memcpy(&lease_duration, lease_duration_ptr, sizeof(uint32_t));
  lease_duration = ntohl(lease_duration);
  click_chatter("!!!!!!!!!!!!! lease_duration: %d", lease_duration);
  IPAddress offeredIPAddress(dm->yiaddr);
  offered_ip = offeredIPAddress.addr();
  
  if(_head == NULL )
  {
    _head = new QueueNode( lease_duration, offered_ip );
    _head->_p = p;
    _head->_next = NULL;
    return;
  }
  
  QueueNode *currNode = _head;
  QueueNode *prevNode = 0;

  while( currNode != NULL && currNode->_lease_time > lease_duration )
  {
    prevNode = currNode;
    currNode = currNode->_next;
  }
  
  QueueNode *newNode = new QueueNode( lease_duration, offered_ip );
  newNode->_p = p;
  
  if(prevNode == 0)
  {
    newNode->_next = _head;
    _head = newNode;
  }
  else
  {
    prevNode->_next = newNode;
    newNode->_next = currNode;
  }
}

Packet* 
DHCPOfferMsgQueue::dequeue()
{
  if(_head == NULL)
    return NULL;

  Packet *q = _head->_p;
  click_chatter("[q] the offered ip : %s" , (_head->_ipAddr).unparse().data());

  QueueNode *oldNode = _head;
  _head = _head->_next;
  delete oldNode;
  
  return q;
}

Packet*
DHCPOfferMsgQueue::remove(const IPAddress &ip_addr)
{
  QueueNode *prev = NULL;
  QueueNode *curr = _head;
  
  while( curr != NULL )
  {
    if(curr->_ipAddr == ip_addr)
    {
      click_chatter("[q] requested ip is in queue!!!");
      Packet *p = curr->_p;
      if( prev == NULL )
	_head = curr->_next;
      else
	prev = curr->_next;
      delete curr;
      
      return p;
    }
    prev = curr;
    curr = curr->_next;
  }
  
  return NULL;
}


EXPORT_ELEMENT(DHCPOfferMsgQueue)
