#include <click/config.h>

#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ether.h>
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
	if (cp_va_parse(conf, this, errh,
			cpElement, "server leases", &_leases,
			cpEnd) < 0 ) {
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
DHCPServerRelease::push(int, Packet *p)
{
	dhcpMessage *release_msg 
		= (dhcpMessage*)(p->data() + sizeof(click_ether) + 
				 sizeof(click_udp) + sizeof(click_ip));
	unsigned char *buf;
	int optionFieldSize;
	EtherAddress eth(release_msg->chaddr);
	
	buf = DHCPOptionUtil::getOption(release_msg->options, 
					DHO_DHCP_SERVER_IDENTIFIER, 
					&optionFieldSize);
	IPAddress incoming_server_id(buf);
	IPAddress server_id = _leases->_ip;
	if (incoming_server_id != server_id) {
		click_chatter("[R] I am not the Server");
		goto done;
	}
	
	_leases->remove(eth);

 done:
	p->kill();
}

EXPORT_ELEMENT(DHCPServerRelease)
ELEMENT_REQUIRES(DHCPOptionUtil)
