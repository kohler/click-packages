#include <click/config.h>

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "dhcp_common.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include "checkdhcpmsg.hh"

#include <clicknet/ip.h>
#include <clicknet/udp.h>

CheckDHCPMsg::CheckDHCPMsg()
{
  add_input();
}

CheckDHCPMsg::~CheckDHCPMsg()
{
}

/*
int 
CheckDHCPMsg::initialize(ErrorHandler *errh)
{
  return 0;
}
*/

int
CheckDHCPMsg::configure(Vector<String> &conf, ErrorHandler *errh)
{
  String tmp;
  if(cp_va_parse(conf, this, errh,
                 cpString, "request or reply", &tmp,
                 cpEnd) < 0)
  {
    return -1;
  }
  
  if( tmp == "request" )
  {
    _checkType = CHECK_REQ;
  }
  else if( tmp == "reply" )
  {
    _checkType = CHECK_REP;
  }
  else
  {
    return -1;
  }

  return 0;
}

void 
CheckDHCPMsg::notify_noutputs(int n)
{
  set_noutputs(n < 2 ? 1 : 2);
}

Packet*
CheckDHCPMsg::simple_action(Packet *p)
{
  dhcpMessage *dm = (dhcpMessage*)(p->data()+sizeof(click_udp)+sizeof(click_ip));
  //dhcpMessage *dm = (dhcpMessage*)(p->data()+sizeof(click_udp));

  if( !( dm->op == DHCP_BOOTREQUEST && _checkType == CHECK_REQ ||
         dm->op == DHCP_BOOTREPLY   && _checkType == CHECK_REP ) )
  {
    click_chatter("%s, %d bad stuff", __FILE__, __LINE__);
    click_chatter("\tdm->op : %x\n", dm->op);
    click_chatter("\t_checkType: %x\n", _checkType);
    
    return drop(p);
  }
  
  uint32_t dm_cookie ;
  uint32_t good_cookie;
  
  memcpy(&dm_cookie, dm->options, 4);
  memcpy(&good_cookie, DHCP_OPTIONS_COOKIE, 4);
  //int good_cookie;

  if( dm_cookie == good_cookie )
  {
    click_chatter("%s, %d good stuff", __FILE__, __LINE__);
    return p;
  }
  else
  {
    click_chatter("%s, %d bad stuff", __FILE__, __LINE__);
    click_chatter("\t good_cookie : %d", good_cookie);
    click_chatter("\t dm_cookie   : %d", dm_cookie);
    return drop(p);
  }
}

Packet*
CheckDHCPMsg::drop(Packet *p)
{
  click_chatter("not a valid dhcp message");
  if(noutputs() == 2)
    output(1).push(p);
  else
    p->kill();
  return 0;
}

EXPORT_ELEMENT(CheckDHCPMsg)
