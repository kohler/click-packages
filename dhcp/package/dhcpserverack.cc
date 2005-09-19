#include <click/config.h>
// include your own config.h if appropriate
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <click/error.hh>
#include <click/confparse.hh>

#include "dhcpserverack.hh"
#include "dhcp_common.hh"
#include "dhcpoptionutil.hh"
#include <clicknet/ip.h>
#include <clicknet/udp.h>

#define DEBUG

DHCPServerACKorNAK::DHCPServerACKorNAK()
{
}

DHCPServerACKorNAK::~DHCPServerACKorNAK()
{
  
}

int 
DHCPServerACKorNAK::initialize(ErrorHandler *)
{
  return 0;
}

int 
DHCPServerACKorNAK::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if( cp_va_parse(conf, this, errh,
		  cpElement, "server leases", &_serverLeases,
		  cpEnd) < 0)
  {
    return -1;
  }
  return 0;
}

void 
DHCPServerACKorNAK::push(int port, Packet *p)
{
  click_chatter("DHCPServerACKorNAK::Push");
  dhcpMessage *req_msg 
    = (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));

  Packet *q;
  unsigned char *buf;
  int size;

  uint32_t ciaddr = req_msg->ciaddr;
  uint32_t giaddr = req_msg->giaddr;
  
  uint32_t server_id;
  buf = DHCPOptionUtil::getOption(req_msg->options, DHO_DHCP_SERVER_IDENTIFIER, &size);
  if( buf != NULL )
    memcpy(&server_id, buf, size);
  else
    server_id = 0;
  
#ifdef DEBUG
  IPAddress server_ip(server_id);
  click_chatter("SERVER IP: %s", server_ip.unparse().data());
#endif  

  uint32_t requested_ip;
  buf = DHCPOptionUtil::getOption( req_msg->options, DHO_DHCP_REQUESTED_ADDRESS, &size );
  if( buf != NULL )
    memcpy( &requested_ip, buf, size );
  else
    requested_ip = 0;
  
#ifdef DEBUG
  IPAddress requested_ipAddr(requested_ip);
  click_chatter("REQ IP : %s", requested_ipAddr.unparse().data());
#endif


  if( ciaddr == 0 && requested_ip != 0 && server_id != 0 )
  {
    // Client's in SELECTING State
#ifdef DEBUG
    click_chatter("------------->Client is in SELECTING state");
#endif
    IPAddress req_ipAddr(requested_ip);
    DHCPServerLeases::Lease *lease_from_ip_map = 
      _serverLeases->ip_lease_map_find(req_ipAddr);
    
    EtherAddress etherAddr(req_msg->chaddr);
    DHCPServerLeases::Lease *lease_from_eth_map =
      _serverLeases->eth_lease_map_find(etherAddr);
    
    if( lease_from_ip_map != NULL && lease_from_eth_map != NULL &&
	lease_from_ip_map == lease_from_eth_map )
    {
      q = make_ack_packet(p, lease_from_eth_map);
      lease_from_eth_map->validate();
    }
    else
    {
      goto cleanup;
    }
  }
  else if ( server_id == 0 && requested_ip != 0 && ciaddr == 0 )
  {
    // INIT-REBOOT state
    IPAddress req_ipAddr(requested_ip);
    EtherAddress etherAddr(req_msg->chaddr);
    bool network_is_correct = false;
#ifdef DEBUG
    click_chatter("------------->Client is in INIT-BOOT state");
    click_chatter("\tserver_id   : %u", server_id);
    click_chatter("\trequsted_ip : %u", requested_ip);
    click_chatter("\trequsted_ip_addr : %s", IPAddress(requested_ip).unparse().data());
    click_chatter("\tciaddr      : %u", ciaddr);
#endif
    if( giaddr == 0 )
    {
      //local
      network_is_correct = 
	req_ipAddr.mask_as_specific(_serverLeases->get_subnet_mask());
    }
    else
    {
      //remote 
      IPAddress g_ipAddr(giaddr);
      network_is_correct = req_ipAddr.mask_as_specific(g_ipAddr);
    }
    
    if(network_is_correct == false)
    {
      //NACK
      click_chatter("BAD network");
      goto cleanup;
    }
    else
      click_chatter("GOOD network");
    
    // in my record?
    DHCPServerLeases::Lease *lease_from_ip_map = 
      _serverLeases->ip_lease_map_find(req_ipAddr);
    DHCPServerLeases::Lease *lease_from_eth_map =
      _serverLeases->eth_lease_map_find(etherAddr);
    
    if(lease_from_ip_map != NULL && lease_from_eth_map != NULL)
    {
      if( lease_from_eth_map != lease_from_ip_map )
      {
	goto cleanup;
      }
      Timestamp now = Timestamp::now();
      
      if( lease_from_ip_map->getEndTime() <  now )
      {
	// NAK
	// _serverLeases->ip_lease_map_rm(req_ipAddr);
	// _serverLeases->eth_lease_map_rm(etherAddr);
	// delete lease_from_ip_map;
	q = make_nak_packet(p, lease_from_ip_map);
      }
      else
      {
	click_chatter("I HAVE A RECORD!!!");
	q = make_ack_packet(p, lease_from_ip_map);
	lease_from_ip_map->validate();
      }
    }
    else
    {
      click_chatter("NO..I don't know");
      goto cleanup;
    }
  }
  else if ( server_id == 0 && requested_ip == 0 && ciaddr != 0 )
  {
    // RENEW or REBIND state
#ifdef DEBUG
    click_chatter("Client is in RENEW or REBIND state");
    click_chatter("renewing ciaddr : %s", IPAddress(ciaddr).unparse().data());
#endif
    
    IPAddress req_ipAddr(requested_ip);
    DHCPServerLeases::Lease *lease_from_ip_map = 
      _serverLeases->ip_lease_map_find(req_ipAddr);
    
    EtherAddress etherAddr(req_msg->chaddr);
    DHCPServerLeases::Lease *lease_from_eth_map =
      _serverLeases->eth_lease_map_find(etherAddr);
    
    if( lease_from_ip_map != NULL && lease_from_eth_map != NULL &&
	lease_from_ip_map == lease_from_eth_map )
    {
      q = make_ack_packet(p, lease_from_ip_map);
      lease_from_ip_map->validate();
      lease_from_ip_map->LeaseExtend();
    }
    else
      goto cleanup;
  }
  else
  {
#ifdef DEBUG
    click_chatter("IN a Weird state");
    click_chatter("\tserver_id   : %u", server_id);
    click_chatter("\trequsted_ip : %u", requested_ip);
    click_chatter("\tciaddr      : %u", ciaddr);
    goto cleanup;
#endif    
  }
  
  click_chatter("sending an ACK packet!!");
  output(0).push(q);

  cleanup: drop(p);
}


Packet*
DHCPServerACKorNAK::make_ack_packet(Packet *p, DHCPServerLeases::Lease *lease)
{
  click_chatter("making an ack packet!");
  dhcpMessage *req_msg =
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  
  WritablePacket *ack_q = Packet::make(sizeof(dhcpMessage));
  memset(ack_q->data(), '\0', ack_q->length());
  dhcpMessage *dhcp_ack =
    reinterpret_cast<dhcpMessage *>(ack_q->data());
  uint8_t *options_ptr;

  dhcp_ack->op = DHCP_BOOTREPLY;
  dhcp_ack->htype = ETH_10MB;
  dhcp_ack->hlen = ETH_10MB_LEN;
  dhcp_ack->hops = 0;
  dhcp_ack->xid = req_msg->xid; // FIX ME: I DON"T what the xid is.!!
  dhcp_ack->secs = 0;
  dhcp_ack->flags = 0;
  dhcp_ack->ciaddr = req_msg->ciaddr;
  click_chatter("dhcp_ack->ciaddr: %u", req_msg->ciaddr);
  dhcp_ack->yiaddr = (lease->getIPAddr()).addr();
  click_chatter("dhcp_ack->yiaddr: %s", (lease->getIPAddr()).unparse().data());
  dhcp_ack->siaddr = 0;
  dhcp_ack->flags = req_msg->flags;
  dhcp_ack->giaddr = req_msg->giaddr;
  memcpy(dhcp_ack->chaddr, req_msg->chaddr, 16);
  
  //option field
  memcpy(dhcp_ack->options, DHCP_OPTIONS_COOKIE, 4);
  options_ptr = dhcp_ack->options + 4;
  *options_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *options_ptr++ = 1;
  *options_ptr++ = DHCP_ACK;

  *options_ptr++ = DHO_DHCP_LEASE_TIME;
  *options_ptr++ = 4;
  uint32_t duration = (lease->getDuration()).sec(); 
  click_chatter("duration :%u", duration);
  duration = htonl(duration);
  memcpy(options_ptr, &duration, 4);
  options_ptr += 4;
  
  *options_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  *options_ptr++ = 4;
  uint32_t server_ip = (_serverLeases->get_server_ip_addr()).addr();
  memcpy(options_ptr, &server_ip, 4);
  options_ptr += 4;

  *options_ptr = DHO_END;
  
  return ack_q;
}

Packet*
DHCPServerACKorNAK::make_nak_packet(Packet *p, DHCPServerLeases::Lease *lease)
{
  click_chatter("MAKING an NAK packet!!!!!!");
  dhcpMessage *req_msg =
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  
  WritablePacket *nak_q = Packet::make(sizeof(dhcpMessage));
  memset(nak_q->data(), '\0', nak_q->length());
  dhcpMessage *dhcp_nak =
    reinterpret_cast<dhcpMessage *>(nak_q->data());
  uint8_t *options_ptr;
  
  dhcp_nak->op = DHCP_BOOTREPLY;
  dhcp_nak->htype = ETH_10MB;
  dhcp_nak->hlen = ETH_10MB_LEN;
  dhcp_nak->hops = 0;
  dhcp_nak->xid = req_msg->xid; // FIX ME: I DON"T what the xid is.!!
  dhcp_nak->secs = 0;
  dhcp_nak->flags = 0;
  dhcp_nak->ciaddr = 0;
  dhcp_nak->yiaddr = 0;
  dhcp_nak->siaddr = 0;
  dhcp_nak->flags = req_msg->flags;
  dhcp_nak->giaddr = req_msg->giaddr;
  memcpy(dhcp_nak->chaddr, req_msg->chaddr, 16);

  //option field
  memcpy(dhcp_nak->options, DHCP_OPTIONS_COOKIE, 4);
  options_ptr = dhcp_nak->options + 4;
  *options_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *options_ptr++ = 1;
  *options_ptr++ = DHCP_NACK;
  
  *options_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  *options_ptr++ = 4;
  uint32_t server_ip = (_serverLeases->get_server_ip_addr()).addr();
  memcpy(options_ptr, &server_ip, 4);
  options_ptr += 4;

  *options_ptr = DHO_END;
  
  return nak_q;
}

Packet*
DHCPServerACKorNAK::drop(Packet *p)
{
  click_chatter("dropping client packet");
  if(noutputs() == 2)
    output(1).push(p);
  else
    p->kill();
  return 0;
}

EXPORT_ELEMENT(DHCPServerACKorNAK)
  
