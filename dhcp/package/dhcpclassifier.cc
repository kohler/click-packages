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
		String s = DHCPOptionUtil::getNextArg(conf[argno]);
		if (s == "discover") {
			_dhcp_msg_to_outport_map.insert(DHCP_DISCOVER, argno);
		} else if (s == "offer") {
			_dhcp_msg_to_outport_map.insert(DHCP_OFFER, argno);
		} else if (s == "request") {
			_dhcp_msg_to_outport_map.insert(DHCP_REQUEST, argno);
		} else if (s == "decline") {
			_dhcp_msg_to_outport_map.insert(DHCP_DECLINE, argno);
		} else if (s == "ack") {
			_dhcp_msg_to_outport_map.insert(DHCP_ACK, argno);
		} else if (s == "nack") {
			_dhcp_msg_to_outport_map.insert(DHCP_NACK, argno);
		} else if (s == "release") {
			_dhcp_msg_to_outport_map.insert(DHCP_RELEASE, argno);
		} else if (s == "inform") {
			_dhcp_msg_to_outport_map.insert(DHCP_INFORM, argno);
		} else if (s == "-") {
			_dhcp_msg_to_outport_map.insert(DHCP_REST, argno);
		}
	}
	return 0;
}

void 
DHCPClassifier::push(int, Packet *p)
{

	dhcpMessage *dm = (dhcpMessage*)(((char *) p->ip_header()) +
					 sizeof(click_ip) + 
					 sizeof(click_udp));	
	int optionFieldSize;
	int portNum;
	unsigned char *msgType = DHCPOptionUtil::getOption(dm->options, 
							   DHO_DHCP_MESSAGE_TYPE, 
							   &optionFieldSize);
	
	if (_dhcp_msg_to_outport_map.find_pair(*msgType)) {
		portNum = _dhcp_msg_to_outport_map.find(*msgType);
	} else {
		portNum =_dhcp_msg_to_outport_map.find(DHCP_REST);
	}
	checked_output_push(portNum, p);
}

#include <click/bighashmap.cc>
#include "dhcpoptionutil.cc"

EXPORT_ELEMENT(DHCPClassifier)
  
