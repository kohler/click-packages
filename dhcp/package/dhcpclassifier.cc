// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
// include your own config.h if appropriate
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

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
	return errh->error("need %d arguments, one per output port", noutputs());

  for( int argno = 0 ; argno < conf.size(); argno++ )
  {
    String s = DHCPOptionUtil::getNextArg(conf[argno]);
    if( s == "discover" )
    {
      click_chatter("setting up discover port");
      _dhcp_msg_to_outport_map.insert(DHCP_DISCOVER, argno);
    }
    else if ( s == "offer" )
    {
      click_chatter("setting up offer port");
      _dhcp_msg_to_outport_map.insert(DHCP_OFFER, argno);
    }
    else if ( s == "request" )
    {
      click_chatter("setting up request port");
      _dhcp_msg_to_outport_map.insert(DHCP_REQUEST, argno);
    }
    else if ( s == "decline" )
    {
      click_chatter("setting up decline port");
      _dhcp_msg_to_outport_map.insert(DHCP_DECLINE, argno);
    }
    else if ( s == "ack" )
    {
      click_chatter("setting up ack port");
      _dhcp_msg_to_outport_map.insert(DHCP_ACK, argno);
    }
    else if ( s == "nack" )
    {
      click_chatter("setting up nack port");
      _dhcp_msg_to_outport_map.insert(DHCP_NACK, argno);
    }
    else if ( s == "release" )
    {
      click_chatter("setting up release port");
      _dhcp_msg_to_outport_map.insert(DHCP_RELEASE, argno);
    }
    else if ( s == "inform" )
    {
      click_chatter("setting up inform port");
      _dhcp_msg_to_outport_map.insert(DHCP_INFORM, argno);
    }
    else if ( s == "-" )
    {
      click_chatter("setting up - port");
      _dhcp_msg_to_outport_map.insert(DHCP_REST, argno);
    }
  }// for
  
  return 0;
}

int
DHCPClassifier::initialize(ErrorHandler *)
{
  return 0;
}


void 
DHCPClassifier::push(int, Packet *p)
{
  dhcpMessage *dm = 
    (dhcpMessage*) (p->data()+sizeof(click_udp)+sizeof(click_ip));
  
  unsigned char *msgType;
  int optionFieldSize;
  msgType = 
      DHCPOptionUtil::getOption(dm->options, DHO_DHCP_MESSAGE_TYPE, &optionFieldSize);

  int portNum;
  if( _dhcp_msg_to_outport_map.find_pair(*msgType) )
  {
    portNum =
      _dhcp_msg_to_outport_map.find(*msgType);
  }
  else
  {
    portNum =
      _dhcp_msg_to_outport_map.find(DHCP_REST);
  }
  
  switch(*msgType)
  {
  case DHCP_DISCOVER:
    click_chatter("[class] DHCP_DISCOVER\n");
    break;
  case DHCP_OFFER:
    click_chatter("[class] DHCP_OFFER\n");
    break;
  case DHCP_REQUEST:
    click_chatter("[class] DHCP_REQUEST\n");
    break;
  case DHCP_DECLINE:
    click_chatter("[class] DHCP_DECLINE\n");
    break;
  case DHCP_ACK:
    click_chatter("[class] DHCP_ACK\n");
    break;
  case DHCP_NACK:
    click_chatter("[class] DHCP_NACK\n");
    break;
  case DHCP_RELEASE:
    click_chatter("[class] DHCP_RELEASE\n");
    break;
  case DHCP_INFORM:
    click_chatter("[class] DHCP_INFORM\n");
    break;
  default:
    click_chatter("[class] UNKNWON TYPE\n");
  }
  
  click_chatter("[class] portNum : %d\n", portNum);
  checked_output_push(portNum, p);
}

#include <click/bighashmap.cc>
#include "dhcpoptionutil.cc"

EXPORT_ELEMENT(DHCPClassifier)
  
