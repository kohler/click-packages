#include <click/config.h>
// include your own config.h if appropriate
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "dhcpclient.hh"
#include "dhcpoptionutil.hh"
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/handlercall.hh>
CLICK_DECLS
#define DEBUG 

static void
_timeout_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_timeout_timer();
}

static void
select_timeout_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_select_timer();
}

static void
resend_discover_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_resend_discover_timer();
}

static void
resend_request_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_resend_request_timer();
}

static void
renew_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_renew_timer();
}

static void
rebind_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_rebind_timer();
}

static void
lease_expired_hook(Timer *, void *thunk)
{
  DHCPClient *e = (DHCPClient*)thunk;
  e->run_lease_expired_timer();
}

DHCPClient::DHCPClient()
  //default parameter
    : _read_file(false),
      _timeout( 60 , 0 ),
      _initial_interval( 4 , 0),
      _retry_interval( 300 , 0 ),
      _select_interval( 1 , 0 ),
      _reboot_timeout( 10 , 0),
      _backoff_cutoff( 16 , 0 ),
      //_timer(this),
      _timeout_timer(_timeout_hook, this),
      _select_timeout_timer(select_timeout_hook, this),
      _resend_discover_timer(resend_discover_hook, this),
      _resend_request_timer(resend_request_hook, this),
      _renew_timer(renew_hook, this),
      _rebind_timer(rebind_hook, this),
      _lease_expired_timer(lease_expired_hook, this),
      _curr_xid(0),
      _lease_duration(0),
      _chosen_offer_pkt(NULL)
{
  set_ninputs(2);
  //set_noutputs(4);
}

DHCPClient::~DHCPClient()
{
  
}

int
DHCPClient::initialize(ErrorHandler *)
{
  _timeout_timer.initialize(this);
  _select_timeout_timer.initialize(this);
  _resend_discover_timer.initialize(this);
  _resend_request_timer.initialize(this);
  _renew_timer.initialize(this);
  _rebind_timer.initialize(this);
  _lease_expired_timer.initialize(this);
  enter_init_state();
  return 0;
}

int 
DHCPClient::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if( cp_va_parse( conf, this, errh,
		   cpEthernetAddress, "HW addr", &_ethAddr,
		   cpEnd) < 0 )
  {
    return -1;
  }
  //_my_ip_h = new HandlerCall(id() + ".client_read");
  
  return 0;
}

void
DHCPClient::notify_noutputs(int n)
{
  set_noutputs( n < 4 ? 3 : 4);
}

Packet*
DHCPClient::drop(Packet *p)
{
  if(noutputs() == 4)
    output(3).push(p);
  else
    p->kill();
  return 0;
}

void 
DHCPClient::push(int, Packet *p)
{
  dhcpMessage *dm = 
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  click_chatter("DHCPClient: we did get to the push function");

  if( dm->xid  != _curr_xid )
  {
    click_chatter("DHCPClient: dropping b/c of wrong xid");
    drop(p);
    return;
  }
  
  EtherAddress myEtherAddr(dm->chaddr);
  if( myEtherAddr != _ethAddr)
  {
    click_chatter("DHCPClient: dropping b/c of wrong ethaddr");
    drop(p);
    return;
  }
  
  int size;
  unsigned char *msgType = 
    DHCPOptionUtil::getOption(dm->options, DHO_DHCP_MESSAGE_TYPE, &size);
  
  switch(*msgType)
  {
  case DHCP_OFFER:
  {
    click_chatter("received DHCP_OFFER!!");

    if(_resend_discover_timer.scheduled())
      _resend_discover_timer.unschedule();
    
    if(!_select_timeout_timer.scheduled())
    {
      _select_timeout_timer.schedule_after_s(_select_interval.sec());
    }
    
    // enqueue it
    output(2).push(p);
    break;
  }
  case DHCP_ACK:
  {
    click_chatter("received DHCP_ACK!!");
    
    enter_bound_state();
    
    if(_chosen_offer_pkt != NULL)
    {
      _chosen_offer_pkt->kill();
      _chosen_offer_pkt = NULL;
    }
    save_lease(p);
    p->kill();
    
    // TODO: ARP?
    // TODO: record the lease time duration.
    
    break;
  }
  case DHCP_NACK:
  {
    click_chatter("received DHCP_NACK!!");
    if(_state == DHCP_CLIENT_BOUND)
    {
      //ignore
    }
    else
    {
      enter_init_state();
    }
    p->kill();
    break;
  }
  default:
  {
    click_chatter("received an UNKNOWN DHCP MSG!!!!!");
  }
  }
}


static int 
write_handler(const String &data, Element *e, void *thunk, ErrorHandler *)
{
  DHCPClient *dc = static_cast<DHCPClient *>(e);
  switch((intptr_t)thunk)
  {
  case 0:
  {
    if(!dc->_read_file)
    {
      String s = cp_uncomment(data);
      DHCPOptionUtil::StringTokenizer tokenizer(cp_uncomment(data));
      String tmp = tokenizer.getNextToken();
      dc->set_my_ip(tmp);
      click_chatter("my ip : %s", tmp.data());

      tmp = tokenizer.getNextToken();
      dc->set_server_ip(tmp);
      click_chatter("server ip : %s", tmp.data());
    
      int32_t start_time;
      cp_integer( tokenizer.getNextToken(), 10, &start_time );
      int32_t end_time;
      cp_integer( tokenizer.getNextToken(), 10, &end_time );
      if(start_time > end_time)
      {
	click_chatter("BAD FORMAT");
      }
      uint32_t duration = end_time - start_time;
      
      click_chatter("now      : %u",Timestamp::now().sec());
      click_chatter("end_time : %u", end_time);
      click_chatter("duration : %u", duration);
      if (end_time > Timestamp::now().sec())
      {
	dc->set_my_lease_time(duration);
	dc->enter_init_reboot_state();
      }
      
      dc->_read_file = true;
    }
    break;
  }
  case 1:
  {
    click_chatter("releasing lease");
    //release lease
    dc->send_dhcp_lease();
    break;
  }
  }
  
  return 0;
}

static String
read_handler(Element *e, void *thunk)
{
  click_chatter("[c]client's read_handler is called!");
  DHCPClient *dc = static_cast<DHCPClient *>(e);
  
  switch((intptr_t)thunk)
  {
  case 0:
  {
    //return "192.168.0.0";
    return (dc->get_my_ip()).unparse();
    break;
  }
  case 1:
  {
    //return "192.168.0.1";
    return (dc->get_server_ip()).unparse();
  }
  case 2:
  {
    String s;
    s = (dc->get_my_ip()).unparse() + " " + 
      (dc->get_server_ip()).unparse() + " " +
      String(dc->get_my_lease_start_time()) + " " + String(dc->get_my_lease_end_time()) +"\n";
    return s;
  }
    default:
      return "";
  }
}

void
DHCPClient::add_handlers()
{
  add_read_handler("client_ip_read", read_handler, (void*)0);
  add_read_handler("server_ip_read", read_handler, (void*)1);
  add_read_handler("lease_read", read_handler, (void*)2);
  add_write_handler("client_write", write_handler, (void*)0);
  add_write_handler("release_write", write_handler, (void*)1);
}


void 
DHCPClient::run_resend_request_timer()
{
  Packet *q = make_request(_chosen_offer_pkt);
  output(0).push(q);
  _curr_backoff = 2 * _curr_backoff;
  
  if(_curr_backoff > _backoff_cutoff.sec())
    _curr_backoff = _backoff_cutoff.sec();
  
  _resend_request_timer.schedule_after_s(DHCPOptionUtil::rand_exp_backoff(_curr_backoff));
}

void
DHCPClient::run_timeout_timer()
{
  click_chatter("no DISCOVER_OFFER received");
  //assert(0);
  _timeout_timer.schedule_after_s(_timeout.sec());
  
  /*_curr_retries++;
  if(_curr_retries < _max_retries)
    enter_init_state();
  else
  assert(0);*/
  
}

void
DHCPClient::run_select_timer()
{
  click_chatter("[c] running select_timer()");
  Packet *p = NULL;
  p = input(1).pull();
  
  click_chatter("[c] p : %p", p);
  
  Packet *q = make_request(p);
  _chosen_offer_pkt = p;
  
  output(0).push(q);
  enter_requesting_state();
}

void
DHCPClient::run_resend_discover_timer()
{
  click_chatter("sending DHCPDISCOVER");
  output(0).push(make_discovery());
  _resend_discover_timer.schedule_after_s(6);
  
  if(_state == DHCP_CLIENT_INIT_STATE)
    enter_selecting_state();
}

void 
DHCPClient::run_renew_timer()
{
  click_chatter("running renew timer");
  enter_renew_state();
}

void 
DHCPClient::run_rebind_timer()
{
  click_chatter("running rebind timer");
  enter_rebind_state();
}

void
DHCPClient::run_lease_expired_timer()
{
  click_chatter("CRAP!! lease expired!!!");
  enter_init_state();
}

Packet*
DHCPClient::make_request_with_ciaddr()
{
  click_chatter("calling make_request_unicast");
  dhcpMessage *request_msg = NULL;
  uint8_t *option_ptr;
  WritablePacket *q = Packet::make(sizeof(dhcpMessage));
  memset(q->data(), '\0', q->length());

  request_msg = (dhcpMessage*) q->data();
  request_msg->op = DHCP_BOOTREQUEST;
  request_msg->htype = ETH_10MB;
  request_msg->hlen = ETH_10MB_LEN;
  request_msg->hops = 0;
  request_msg->xid = random();

  _curr_xid = request_msg->xid;

  request_msg->secs = 0;
  request_msg->flags = 0;
  request_msg->ciaddr = _my_ip.addr();
  request_msg->yiaddr = 0;
  request_msg->siaddr = 0;
  request_msg->giaddr = 0;
  memcpy(request_msg->chaddr,
	 _ethAddr.data(),
	 16);
  memcpy(request_msg->options, DHCP_OPTIONS_COOKIE, 4);
  option_ptr = request_msg->options + 4;
  *option_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *option_ptr++ = 1;
  *option_ptr++ = DHCP_REQUEST;

  *option_ptr = DHO_END;

  return q;
}

Packet* 
DHCPClient::make_request(Packet *p)
{
  dhcpMessage *offer_dm = 
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  
  dhcpMessage *request_msg = NULL;
  uint8_t *option_ptr;
  int size;
  
  WritablePacket *q = Packet::make(sizeof(dhcpMessage));
  memset(q->data(), '\0', q->length());
  
  request_msg = (dhcpMessage*) q->data();
  request_msg->op = DHCP_BOOTREQUEST;
  request_msg->htype = ETH_10MB;
  request_msg->hlen = ETH_10MB_LEN;
  request_msg->hops = 0;
  request_msg->xid = offer_dm->xid;
  request_msg->secs = 0;
  request_msg->flags = 0; //set 'BROADCAST' flag if client requeires broadcast reply
  request_msg->ciaddr = 0;
  request_msg->yiaddr = 0; 
  request_msg->siaddr = 0;
  request_msg->giaddr = 0;
  memcpy(request_msg->chaddr,
	 _ethAddr.data(),
	 16);

  //option field
  memcpy(request_msg->options, DHCP_OPTIONS_COOKIE, 4);
  option_ptr = request_msg->options + 4;
  *option_ptr++ = DHO_DHCP_MESSAGE_TYPE;
  *option_ptr++ = 1;
  *option_ptr++ = DHCP_REQUEST;
  
  // requested ip address
  if(_state == DHCP_CLIENT_SELECTING_STATE || _state == DHCP_CLIENT_INIT_REBOOT ||
     _state == DHCP_CLIENT_REBOOTING)
  {
    //must 
    *option_ptr++ = DHO_DHCP_REQUESTED_ADDRESS;
    size = 4;
    uint32_t requested_addr = offer_dm->yiaddr;
    
#ifdef DEBUG
    {
      IPAddress client_ip(requested_addr);
      click_chatter("--->client ip : %s", client_ip.unparse().data());
    }
#endif
    
    *option_ptr++ = size;
    memcpy(option_ptr, &requested_addr, size);
    option_ptr+= size;
  }
  else if(_state == DHCP_CLIENT_BOUND || _state == DHCP_CLIENT_RENEWING)
  {
    //must not 
  }
  else
  {
    click_chatter("STATE : %d", _state);
    assert(0);
  }
  
  //endian problem here
  // request lease time
  unsigned char *lease_time =
    DHCPOptionUtil::getOption(offer_dm->options, DHO_DHCP_LEASE_TIME, &size);

  click_chatter("lease_time  : %x", lease_time);
  
  if(lease_time == NULL)
  {
    click_chatter("\tno lease time specified!!!!!!");
    //assert(0);
  }
  else
  {
    uint32_t lease_time_value;
    memcpy(&lease_time_value, lease_time, 4);
    lease_time_value = ntohl(lease_time_value);
    click_chatter("\tlease time specified : %d", lease_time_value);
    
    *option_ptr++ = DHO_DHCP_LEASE_TIME;
    *option_ptr++ = size;
    lease_time_value = htonl(lease_time_value);
    memcpy(option_ptr, &lease_time_value, size);
    option_ptr+=size;
  }
  
  // server identifier
  if(_state == DHCP_CLIENT_SELECTING_STATE)
  {
    unsigned char *server_id =
      DHCPOptionUtil::getOption(offer_dm->options, DHO_DHCP_SERVER_IDENTIFIER, &size);

#ifdef DEBUG
    {
      IPAddress server_ip(server_id);
      if( server_ip == IPAddress("192.168.10.9") )
	click_chatter("--->server_ip: %s", server_ip.unparse().data());
      else
	click_chatter("--->NO");
    }
#endif
    
    *option_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
    *option_ptr++ = size;
    memcpy(option_ptr, server_id, size);
  }
  else if(_state == DHCP_CLIENT_INIT_REBOOT || 
	  _state == DHCP_CLIENT_BOUND ||
	  _state == DHCP_CLIENT_RENEWING ||
	  _state == DHCP_CLIENT_REBINDING )
  {
    click_chatter("\tdon't put server id in option");
  }
  
  return q;
}

void
DHCPClient::send_dhcp_lease()
{
  Packet *q = make_release();
  output(1).push(q); //unicast;
}

Packet *
DHCPClient::make_release()
{
  dhcpMessage *release_msg;
  uint8_t *option_ptr;
  WritablePacket *q = Packet::make(sizeof(dhcpMessage));
  memset(q->data(), '\0', q->length());
  
  release_msg = (dhcpMessage*) q->data();
  release_msg->op = DHCP_BOOTREQUEST;
  release_msg->htype = ETH_10MB;
  release_msg->hlen = ETH_10MB_LEN;
  release_msg->hops = 0;
  release_msg->xid = random(); // long-32bit
  
  _curr_xid = release_msg->xid;
  release_msg->secs = 0;
  release_msg->flags = 0;
  release_msg->ciaddr = _my_ip.addr();
  release_msg->yiaddr = 0;
  release_msg->siaddr = 0;
  release_msg->giaddr = 0;
  memcpy(release_msg->chaddr, 
         _ethAddr.data(), 
         16);
  
  // option field
  memcpy(release_msg->options, DHCP_OPTIONS_COOKIE, 4);
  option_ptr = release_msg->options + 4;
  *option_ptr++ = DHO_DHCP_MESSAGE_TYPE; //type
  *option_ptr++ = 1;
  *option_ptr++ = DHCP_RELEASE;

  *option_ptr++ = DHO_DHCP_SERVER_IDENTIFIER;
  *option_ptr++ = 4;
  uint32_t server_id = _server_ip.addr();
  memcpy(option_ptr, &server_id , 4);
  
  *option_ptr = DHO_END;
  return q;
}

Packet *
DHCPClient::make_deline()
{
  return NULL;
}


Packet *
DHCPClient::make_discovery()
{
  dhcpMessage *discover_msg;
  uint8_t *option_ptr;
  //char magic_cookie[4];
  //memcpy(magic_cookie, DHCP_OPTIONS_COOKIE, 4);
  
  //click_ether *e;
  WritablePacket *q = Packet::make(sizeof(dhcpMessage));
  memset(q->data(), '\0', q->length());
  
  discover_msg = (dhcpMessage*) q->data();
  discover_msg->op = DHCP_BOOTREQUEST;
  discover_msg->htype = ETH_10MB;
  discover_msg->hlen = ETH_10MB_LEN;
  discover_msg->hops = 0;
  discover_msg->xid = random(); // long-32bit
  
  _curr_xid = discover_msg->xid;
  
  discover_msg->secs = 0;
  discover_msg->flags = 0;
  discover_msg->ciaddr = 0;
  discover_msg->yiaddr = 0;
  discover_msg->siaddr = 0;
  discover_msg->giaddr = 0;
  memcpy(discover_msg->chaddr, 
         _ethAddr.data(), 
         16);
  
  // option field
  memcpy(discover_msg->options, DHCP_OPTIONS_COOKIE, 4);
  option_ptr = discover_msg->options + 4;
  *option_ptr++ = DHO_DHCP_MESSAGE_TYPE; //type
  *option_ptr++ = 1;
  *option_ptr++ = DHCP_DISCOVER;

  if(_my_ip)
  {
    click_chatter("-->inserting DHO_DHCP_REQUESTED_ADDRESS");
    *option_ptr++ = DHO_DHCP_REQUESTED_ADDRESS;
    *option_ptr++ = 4;
    memcpy(option_ptr, _my_ip.data(), 4);
    option_ptr += 4;
  }
  
  if(_lease_duration > 0)
  {
    click_chatter("-->inserting DHO_DHCP_LEASE_TIME");
    *option_ptr++ = DHO_DHCP_LEASE_TIME;
    *option_ptr++ = 4;
    memcpy(option_ptr, &_lease_duration, 4);
    option_ptr += 4;
  }

    
  *option_ptr = DHO_END;
  
  return q;
}

void 
DHCPClient::enter_init_state()
{
  click_chatter("[c] Enter INIT STATE");
  _state = DHCP_CLIENT_INIT_STATE;
  //_retry_discover_timer.schedule_after_s(15);
  if(_renew_timer.scheduled())
    _renew_timer.unschedule();
  if(_rebind_timer.scheduled())
    _rebind_timer.unschedule();
  if(_lease_expired_timer.scheduled())
    _lease_expired_timer.unschedule();
  if(_resend_request_timer.scheduled())
    _resend_request_timer.unschedule();
  if(_resend_discover_timer.scheduled())
    _resend_discover_timer.unschedule();
  if(_select_timeout_timer.scheduled())
    _select_timeout_timer.unschedule();

  _t1_timestamp_sec  = 0;
  _t2_timestamp_sec  = 0;
  _lease_expired_sec = 0;
  
  if(_timeout_timer.scheduled())
    _timeout_timer.unschedule();
  _timeout_timer.schedule_after_s(_timeout.sec());
  
  _resend_discover_timer.schedule_after_s(random() % 10);
}

void
DHCPClient::enter_init_reboot_state()
{
  click_chatter("[c] Enter INIT_REBOOT STATE");
  if(_resend_discover_timer.scheduled())
    _resend_discover_timer.unschedule();

  Packet *q = make_request_with_ciaddr();
  output(0).push(q); // broadcast;
  _lease_expired_timer.schedule_after_s(60); // 10 secs? 
  enter_rebooting_state();
}

void
DHCPClient::enter_rebooting_state()
{
  _state = DHCP_CLIENT_REBOOTING;
}

void
DHCPClient::enter_selecting_state()
{
  _state = DHCP_CLIENT_SELECTING_STATE;
  //output(0).push(make_discovery());
}

void
DHCPClient::enter_bound_state()
{
  _state = DHCP_CLIENT_BOUND;
  _timeout_timer.unschedule();
  _resend_request_timer.unschedule();
  _curr_backoff = _initial_interval.sec();
}

void 
DHCPClient::enter_requesting_state()
{
  _state = DHCP_CLIENT_REQUESTING_STATE;
  _curr_backoff = _initial_interval.sec();
  _resend_request_timer.schedule_after_s(DHCPOptionUtil::rand_exp_backoff(_curr_backoff));
}

void 
DHCPClient::enter_renew_state()
{
  // send request via unicast
  // must not include server id
  Packet *q = make_request_with_ciaddr();
  output(1).push(q); // unicast;
  
  uint32_t next_timeout_sec = ( _t2_timestamp_sec - Timestamp::now().sec() ) / 2;
  if(next_timeout_sec > 60) 
    _renew_timer.schedule_after_s(next_timeout_sec);
}


void 
DHCPClient::enter_rebind_state()
{
  Packet *q = make_request_with_ciaddr();
  output(0).push(q); //broadcast;
  
  uint32_t next_timeout_sec = ( _lease_expired_sec - Timestamp::now().sec() ) / 2;
  if(next_timeout_sec > 60)
    _rebind_timer.schedule_after_s(next_timeout_sec);
}

void 
DHCPClient::set_my_ip(const String &ip)
{
  _my_ip = IPAddress(ip);
}

void 
DHCPClient::set_server_ip(const String &ip)
{
  _server_ip = IPAddress(ip);
}

const IPAddress&
DHCPClient::get_my_ip() const
{
  return _my_ip;
}

const IPAddress& 
DHCPClient::get_server_ip() const
{
  return _server_ip;
}

void 
DHCPClient::set_my_lease_time(const int &time)
{
  _lease_duration = time;
}

const uint32_t 
DHCPClient::get_my_lease_duration() const
{
  return _lease_duration;
}

const uint32_t 
DHCPClient::get_my_lease_start_time() const
{
  return _start_timestamp_sec;
}
const uint32_t 
DHCPClient::get_my_lease_end_time() const
{
  return _lease_expired_sec;
}

void 
DHCPClient::save_lease(Packet *p)
{
  dhcpMessage *dm = 
    (dhcpMessage*)(p->data() + sizeof(click_udp) + sizeof(click_ip));
  int size;
  
  if(p == NULL) assert(false); // for now

  unsigned char *msgType = 
    DHCPOptionUtil::getOption(dm->options, DHO_DHCP_MESSAGE_TYPE, &size);
  if( *msgType != DHCP_ACK )
  {
    click_chatter("WARNING NOT an ACK pkt. Can't save lease");
    return;
  }

  IPAddress my_new_ip(dm->yiaddr);
  if( _my_ip != my_new_ip )
  {
    _my_ip = my_new_ip;
  }

  unsigned char *lease_time =
    DHCPOptionUtil::getOption(dm->options, DHO_DHCP_LEASE_TIME, &size);
  
  click_chatter("lease_time  : %p", lease_time); //xxx
  click_chatter("\tlease time specified2 : %d", _lease_duration);
  
  memcpy(&_lease_duration, lease_time, 4);
  _lease_duration = htonl(_lease_duration);

  
#ifdef DEBUG
  click_chatter("\tlease time specified2 : %d", _lease_duration);
  click_chatter("\tsize                  : %d",size);
#endif  
  
  unsigned char *server_id =
    DHCPOptionUtil::getOption(dm->options, DHO_DHCP_SERVER_IDENTIFIER, &size);

  IPAddress new_server_ip(server_id);
  if(_server_ip != new_server_ip)
  {
    _server_ip = new_server_ip;
  }
#ifdef DEBUG
  IPAddress siaddr(dm->siaddr);
  if(new_server_ip == siaddr)
  {
    click_chatter("DHCP SERVER ID and siaddr are the same!!");
  }
#endif
  
  // set up T1 , T2  and the lease expiration timers 
  uint32_t now_sec = Timestamp::now().sec();
  _start_timestamp_sec = now_sec;
  _t1_timestamp_sec = _lease_duration/2 + now_sec;
  _t2_timestamp_sec = (_lease_duration * 7 / 8) + now_sec;
  _lease_expired_sec = _lease_duration + now_sec; 
  
  click_chatter("now sec  : %u", now_sec);
  click_chatter("t1  sec  : %u", _t1_timestamp_sec);
  click_chatter("t2  sec  : %u", _t2_timestamp_sec);
  click_chatter("exp sec  : %u", _lease_expired_sec);
  
  if(_renew_timer.scheduled())
    _renew_timer.unschedule();
  _renew_timer.schedule_after_s( _lease_duration/2 + random()%10 );
  
  if(_rebind_timer.scheduled())
    _rebind_timer.unschedule();
  _rebind_timer.schedule_after_s( (_lease_duration * 7 / 8) + random()%10 );

  if(_lease_expired_timer.scheduled())
    _lease_expired_timer.unschedule();
  _lease_expired_timer.schedule_after_s( _lease_duration );

  // TODO: save it to a file !! using DriverManager!!?
}

EXPORT_ELEMENT(DHCPClient)

