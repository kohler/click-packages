#include <click/config.h>
// include your own config.h if appropriate
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

#include "dhcp_common.hh"
#include "dhcpserveroffer.hh"
#include "dhcpoptionutil.hh"


#define OFFER_TIMEOUT 10
#define OFFER_NO_TIMEOUT 1

DHCPServerOffer::DHCPServerOffer()
    :_send_offer_timer(this)
{

}

DHCPServerOffer::~DHCPServerOffer()
{
  
}

int
DHCPServerOffer::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if( cp_va_parse(conf, this, errh,
		  cpElement, "server leases", &_serverLeases,
		  cpEnd) < 0 )
  {
    return -1;
  }
  return 0;
}


int 
DHCPServerOffer::initialize(ErrorHandler *)
{
  _send_offer_timer.initialize(this);
  return 0;
}

void
DHCPServerOffer::notify_noutputs(int n)
{
  set_noutputs(n < 2 ? 1 : 2);
}

void 
DHCPServerOffer::notify_ninputs(int n)
{
  set_ninputs(n < 2? 1 : 2);
}

void 
DHCPServerOffer::push(int port, Packet *p)
{
  if(port == 0)
  {
    click_chatter("DHCPServerOffer::push. This is a dhcp offer packet");
    dhcpMessage *discover_msg 
      = (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
    int optionFieldSize;
    unsigned char *buf;
    
    EtherAddress etherAddr(discover_msg->chaddr);
    click_chatter("mac addr: %s", etherAddr.unparse().data());
    
    DHCPServerLeases::Lease *lease = _serverLeases->get_client_ip(etherAddr);
    IPAddress client_request_ip;
    uint32_t lease_duration = 0;
    
    if( lease == NULL )
    {
      buf =
	DHCPOptionUtil::getOption(discover_msg->options, DHO_DHCP_REQUESTED_ADDRESS, &optionFieldSize);
    
      if(buf == NULL)
      {
	if(_serverLeases->reserve_any_ip(client_request_ip) == false)
	{
	  click_chatter("NO available IP left");
	}
      }
      else
      {
	client_request_ip = IPAddress(buf);
	click_chatter("client tries to request: %s", client_request_ip.unparse().data());
      
	if( !_serverLeases->can_ip_be_reserved(client_request_ip) )
	{
	  click_chatter("requested ip cannot be reservered! ");
	  if(_serverLeases->reserve_any_ip(client_request_ip) == false)
	  {
	    click_chatter("NO available lease left");
	    p->kill();
	    return;
	  }
	  else
	  {
	    click_chatter("RESERVING IP : %s", client_request_ip.unparse().data());
	  }
	}
	else
	{
	  click_chatter("requested ip can be reservered! ");
	  if(_serverLeases->reserve_this_ip(client_request_ip) == false)
	  {
	    click_chatter("Dropping the DHCPDiscover on the floor");
	    p->kill();
	    return;
	  }
	}
      } // if(buf == NULL)
    } // if(lease == NULL)
    else
    {
      buf =
	DHCPOptionUtil::getOption(discover_msg->options, DHO_DHCP_REQUESTED_ADDRESS, &optionFieldSize);
    
      if( buf == NULL )
      {
	// nothing matched with the lease
	if( lease->getEtherAddr() == etherAddr) 
	{
	  client_request_ip = lease->getIPAddr();
	}
	else
	{
	  if(_serverLeases->reserve_any_ip(client_request_ip) == false)
	  {
	    click_chatter("NO available lease left");
	    p->kill();
	    return;
	  }
	}
      }
      else
      {
	client_request_ip = IPAddress(buf);
	if( lease->getEtherAddr() == etherAddr && 
	    lease->getIPAddr() == client_request_ip )
	{
	  // good to go
	}
	else
	{
	  if(_serverLeases->reserve_any_ip(client_request_ip) == false )
	  {
	    click_chatter("NO available lease left");
	    p->kill();
	    return;
	  }
	}
      }
    }
    click_chatter("My final answer to the requested IP: %s", client_request_ip.unparse().data());
  
    buf = DHCPOptionUtil::getOption(discover_msg->options, DHO_DHCP_LEASE_TIME, &optionFieldSize);
    if( buf == NULL && lease != NULL && lease->getEtherAddr() == etherAddr )
    {
      lease_duration = lease->getDuration();
    }
    else if (buf == NULL && lease == NULL )
    {
      lease_duration = _serverLeases->get_default_duration();
    }
    else if ( buf != NULL )
    {
      char *lease_duration_ptr = (char*)&lease_duration;
      for(int i = 0; i < 4; i++)
      {
	lease_duration_ptr[3-i] = buf[i];
      }
    
      if( lease_duration > _serverLeases->get_max_duration() )
	lease_duration = _serverLeases->get_max_duration();
    }
    
    if( lease_duration == 0 )
      lease_duration = _serverLeases->get_default_duration();

  
    click_chatter("max duration     : %u", _serverLeases->get_max_duration());
    click_chatter("default duration : %u", _serverLeases->get_default_duration());
    click_chatter("My final answer to the lease time: %u", lease_duration);
    
    Timestamp now = Timestamp::now();
    
    DHCPServerLeases::Lease *new_lease = _serverLeases->ip_lease_map_find(client_request_ip);
    if(new_lease == NULL)
    {
      new_lease 
	= new DHCPServerLeases::Lease( etherAddr, client_request_ip, now, 
				       Timestamp(now.sec() + lease_duration, 0) );
      click_chatter("now  : %u", now.sec());
      
      _serverLeases->eth_lease_map_insert( etherAddr, new_lease );
      _serverLeases->ip_lease_map_insert( client_request_ip, new_lease );
    }
    
    _lease_fifo_queue.enqueue(new_lease, p);
    if(noutputs()==2)
    {
      click_chatter("Let me Do a ICMP Ping to verify if this is OK");
      _curr_icmp_dst_ipAddr = client_request_ip;
      WritablePacket *q = Packet::make((unsigned int)0);
      output(1).push(q);
      _send_offer_timer.schedule_after_ms(OFFER_TIMEOUT);
    }
    else
    {
      _send_offer_timer.schedule_after_ms(OFFER_NO_TIMEOUT);
    }

  }
  else if(port == 1) // ICMP RESPOND MSG.
  {
    click_chatter("[o] Received an ICMP echo-reply message!");
    if(ninputs() != 2)
    {
      assert(false); //paranoid;
    }
    //get src from icmp 
    const click_ip *iph = p->ip_header();
    IPAddress srcIPAddr(iph->ip_src);
    DHCPServerLeases::Lease *lease;
    
    //find the lease
    lease = _serverLeases->ip_lease_map_find(srcIPAddr);
    
    IPAddress client_ip;
    click_chatter("THis is a ping message");
    _serverLeases->reserve_any_ip(client_ip);
    lease->setIPAddr(client_ip);
    
    //TODO: ICMP Ping again;
    _lease_fifo_queue.enqueue(lease, p);

    if(_send_offer_timer.scheduled())
      _send_offer_timer.schedule_after_ms(OFFER_TIMEOUT);
    _send_offer_timer.schedule_after_ms(OFFER_TIMEOUT);
  }
  
}

void
DHCPServerOffer::run_timer()
{
  click_chatter("[o] Time out!! Time to send an offer");
  if(_send_offer_timer.scheduled())
    _send_offer_timer.unschedule();
  
  DHCPServerOffer::LeaseNode *leaseNode  = 
    _lease_fifo_queue.dequeue();
  Packet *q = make_offer_packet(leaseNode);
  delete leaseNode;
  output(0).push(q); 
}

Packet*
DHCPServerOffer::make_offer_packet(DHCPServerOffer::LeaseNode *leaseNode)
{
  Packet *p = leaseNode->dm;
  dhcpMessage *discover_dm = 
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  
  DHCPServerLeases::Lease *lease = leaseNode->v;
  
  WritablePacket *offer_q = Packet::make(sizeof(dhcpMessage));
  memset(offer_q->data(), '\0', offer_q->length());
  dhcpMessage *dhcp_offer = 
    reinterpret_cast<dhcpMessage *>(offer_q->data());
  uint8_t *option_ptr;

  dhcp_offer->op = DHCP_BOOTREPLY;
  dhcp_offer->htype = ETH_10MB;
  dhcp_offer->hlen = ETH_10MB_LEN;
  dhcp_offer->hops = 0;
  dhcp_offer->xid = discover_dm->xid; 
  dhcp_offer->secs = 0;
  dhcp_offer->flags = 0;
  dhcp_offer->ciaddr = 0;
  dhcp_offer->yiaddr = (lease->getIPAddr()).addr();
  dhcp_offer->siaddr = 0;
  dhcp_offer->giaddr = 0;
  memcpy(dhcp_offer->chaddr, discover_dm->chaddr, 16);
  
  //option field
  memcpy(dhcp_offer->options, DHCP_OPTIONS_COOKIE, 4);
  option_ptr = dhcp_offer->options + 4;
  *option_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *option_ptr++ = 1;
  *option_ptr++ = DHCP_OFFER;
  
  *option_ptr++ = DHO_DHCP_LEASE_TIME;
  uint32_t duration = (lease->getDuration()).sec(); 
  *option_ptr++ = 4;
  memcpy(option_ptr, &duration, 4);
  option_ptr += 4;

  *option_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  uint32_t server_ip = (_serverLeases->get_server_ip_addr()).addr();
  *option_ptr++ = 4;
  memcpy(option_ptr, &server_ip, 4);
  option_ptr += 4;
  
  *option_ptr = DHO_END;
  
  return offer_q;
}

static String
read_handler(Element *e, void *thunk)
{
  DHCPServerOffer *dso = static_cast<DHCPServerOffer*>(e);
  switch((intptr_t)thunk)
  {
  case 0:
  {
    return dso->get_curr_icmp_dst_ipAddr().unparse();
  }
  case 1:
  {
    return dso->getServerLeases()->get_server_ip_addr().unparse();
  }
  }
}

void
DHCPServerOffer::add_handlers()
{
  add_read_handler("dhcp_icmp_ping_dst", read_handler, (void*)0);
  add_read_handler("dhcp_icmp_ping_src", read_handler, (void*)0);
}

const IPAddress &
DHCPServerOffer::get_curr_icmp_dst_ipAddr() const
{
  return _curr_icmp_dst_ipAddr;
}

const DHCPServerLeases* 
DHCPServerOffer::getServerLeases() const
{
  return _serverLeases;
}

DHCPServerOffer::LeaseFIFOQueue::LeaseFIFOQueue()
    :_lease_fifo_head(NULL),
     _lease_fifo_tail(NULL)
{
  
}

DHCPServerOffer::LeaseFIFOQueue::~LeaseFIFOQueue()
{
  LeaseNode *node = _lease_fifo_head;
  LeaseNode *nextNode;
  while( node != NULL )
  {
    nextNode = node->next;
    delete node;
    node = nextNode;
  }// while
}

void 
DHCPServerOffer::LeaseFIFOQueue::enqueue(DHCPServerLeases::Lease *lease, Packet* p)
{
  LeaseNode *node = new LeaseNode;
  node->v = lease;
  node->dm = p;
  node->next = NULL;

  if(_lease_fifo_head == NULL)
  {
    _lease_fifo_head = node;
    _lease_fifo_tail = _lease_fifo_head;
    return;
  }

  _lease_fifo_tail->next = node;
  _lease_fifo_tail = _lease_fifo_tail->next;
  
}

DHCPServerOffer::LeaseNode *
DHCPServerOffer::LeaseFIFOQueue::dequeue()
{
  if( _lease_fifo_head == NULL ) return NULL;
  
  LeaseNode *dequeued_node = _lease_fifo_head;
  
  if(_lease_fifo_head == _lease_fifo_tail) 
  {
    _lease_fifo_head = _lease_fifo_tail = NULL;
  }
  else
  {
    _lease_fifo_head = _lease_fifo_head->next;
  }
  return dequeued_node;
}


EXPORT_ELEMENT(DHCPServerOffer)
