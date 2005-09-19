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
#include "dhcpserverrelease.hh"
#include "dhcpoptionutil.hh"

DHCPServerRelease::DHCPServerRelease()
{
}

DHCPServerRelease::~DHCPServerRelease()
{

}

int
DHCPServerRelease::configure(Vector<String> &conf, ErrorHandler *errh)
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
DHCPServerRelease::initialize(ErrorHandler *)
{
  return 0;
}

void
DHCPServerRelease::push(int port, Packet *p)
{
  dhcpMessage *release_msg 
    = (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  unsigned char *buf;
  int optionFieldSize;
  
  buf =
    DHCPOptionUtil::getOption(release_msg->options, DHO_DHCP_SERVER_IDENTIFIER, &optionFieldSize);
  IPAddress incoming_server_id(buf);
  IPAddress server_id = _serverLeases->get_server_ip_addr();
  if(incoming_server_id != server_id)
  {
    click_chatter("[R] I am not the Server");
    return;
  }
  
  IPAddress ipAddr(release_msg->ciaddr);
  EtherAddress ethAddr(release_msg->chaddr);
  DHCPServerLeases::Lease *lease = _serverLeases->ip_lease_map_find(ipAddr);
  _serverLeases->ip_lease_map_rm(ipAddr);
  _serverLeases->eth_lease_map_rm(ethAddr);
  delete lease;
  p->kill();
}

EXPORT_ELEMENT(DHCPServerRelease)
