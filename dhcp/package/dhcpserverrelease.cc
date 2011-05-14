#include <click/config.h>

#include <click/error.hh>
#include <click/args.hh>
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
    return Args(conf, this, errh)
	.read_mp("LEASES", ElementCastArg("DHCPLeaseTable"), _leases)
	.complete();
}

void
DHCPServerRelease::push(int, Packet *p)
{
	dhcpMessage *release_msg
		= (dhcpMessage*)(p->data() + sizeof(click_ether) +
				 sizeof(click_udp) + sizeof(click_ip));
	EtherAddress eth(release_msg->chaddr);

	const uint8_t *opt = DHCPOptionUtil::fetch(p, DHO_DHCP_SERVER_IDENTIFIER, 4);
	IPAddress incoming_server_id(opt);
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
