// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>

#include "dhcp_common.hh"
#include "dhcpclassifier.hh"
#include "dhcpoptionutil.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>


DHCPClassifier::DHCPClassifier()
    : _dhcp_msg_to_outport_map(-1)
{
}

DHCPClassifier::~DHCPClassifier()
{
}

int
DHCPClassifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (conf.size() != noutputs())
	return errh->error("need %d arguments, one per output port",
			   noutputs());

    for (int argno = 0 ; argno < conf.size(); argno++) {
	String s = conf[argno];
	if (s == "discover") {
	    _dhcp_msg_to_outport_map[DHCP_DISCOVER] = argno;
	} else if (s == "offer") {
	    _dhcp_msg_to_outport_map[DHCP_OFFER] = argno;
	} else if (s == "request") {
	    _dhcp_msg_to_outport_map[DHCP_REQUEST] = argno;
	} else if (s == "decline") {
	    _dhcp_msg_to_outport_map[DHCP_DECLINE] = argno;
	} else if (s == "ack") {
	    _dhcp_msg_to_outport_map[DHCP_ACK] = argno;
	} else if (s == "nack") {
	    _dhcp_msg_to_outport_map[DHCP_NACK] = argno;
	} else if (s == "release") {
	    _dhcp_msg_to_outport_map[DHCP_RELEASE] = argno;
	} else if (s == "inform") {
	    _dhcp_msg_to_outport_map[DHCP_INFORM] = argno;
	} else if (s == "-") {
	    _dhcp_msg_to_outport_map[DHCP_REST] = argno;
	} else
            return errh->error("unknown DHCP type %<%s%>", s.printable().c_str());
    }
    return 0;
}

void 
DHCPClassifier::push(int, Packet *p)
{
    const uint8_t *mtype = DHCPOptionUtil::fetch(p, DHO_DHCP_MESSAGE_TYPE, 1);
    int port = -1;
    if (mtype)
	port = _dhcp_msg_to_outport_map.get(*mtype);
    if (port < 0)
	port = _dhcp_msg_to_outport_map.get(DHCP_REST);
    checked_output_push(port, p);
}

EXPORT_ELEMENT(DHCPClassifier)
ELEMENT_REQUIRES(DHCPOptionUtil)  
