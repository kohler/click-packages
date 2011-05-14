#include <click/config.h>

#include "dhcpclient.hh"
#include "dhcpoptionutil.hh"
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/handlercall.hh>
#include <clicknet/ether.h>
CLICK_DECLS
#define DEBUG

DHCPClient::DHCPClient()
//default parameter
    : _timeout(60, 0),
      _initial_interval(4, 0),
      _retry_interval(300, 0),
      _select_interval(1, 0),
      _reboot_timeout(10, 0),
      _backoff_cutoff(16, 0),
      _curr_xid(0),
      _lease_duration(0),
      _offers(0),
      _best_offer(0),
      _lease_call(0)
{
    for (int i = 0; i < NTIMERS; i++)
	_timers[i].assign(this);
}

DHCPClient::~DHCPClient()
{
}

int
DHCPClient::initialize(ErrorHandler *errh)
{
    for (int i = 0; i < NTIMERS; i++)
	_timers[i].initialize(this);
    enter_init_state();
    if (_lease_call && _lease_call->initialize_write(this, errh) < 0)
	return -1;
    return 0;
}

int
DHCPClient::configure(Vector<String> &conf, ErrorHandler *errh)
{
    HandlerCall lease_call;
    if (Args(conf, this, errh)
	.read_mp("ETH", _ethAddr)
	.read_mp("IP", _my_ip)
	.read("IPADDR", _my_ip) // deprecated
	.read("LEASE_CALL", HandlerCallArg(HandlerCall::writable), lease_call)
	.complete() < 0)
	return -1;
    _lease_call = (lease_call ? new HandlerCall(lease_call) : 0);
    return 0;
}

void DHCPClient::cleanup(CleanupStage)
{
    while (Packet *p = _offers) {
	_offers = p->next();
	p->kill();
    }
    if (_best_offer)
	_best_offer->kill();
    _best_offer = 0;
    delete _lease_call;
}

void DHCPClient::save_lease(Packet *p)
{
    // assert(is DHCP_ACK);
    const dhcpMessage *dm = reinterpret_cast<const dhcpMessage *>(p->transport_header() + sizeof(click_udp));
    _my_ip = IPAddress(dm->yiaddr);

    if (const uint8_t *leaseo = DHCPOptionUtil::fetch(p, DHO_DHCP_LEASE_TIME, 4)) {
	_lease_duration = (leaseo[0] << 24) | (leaseo[1] << 16) | (leaseo[2] << 8) | leaseo[3];
  
	// set up T1 , T2  and the lease expiration timers 
	uint32_t now_sec = Timestamp::now().sec();
	_start_timestamp_sec = now_sec;
	_t1_timestamp_sec = _lease_duration/2 + now_sec;
	_t2_timestamp_sec = (_lease_duration * 7 / 8) + now_sec;
	_lease_expired_sec = _lease_duration + now_sec; 
  
	_timers[T_RENEW].schedule_after_sec(_lease_duration/2 + click_random(0, 9));
	_timers[T_REBIND].schedule_after_sec((_lease_duration * 7 / 8) + click_random(0, 9));
	_timers[T_LEASE_EXPIRED].schedule_after_sec(_lease_duration);
    } else {
	_start_timestamp_sec = _t1_timestamp_sec
	    = _t2_timestamp_sec = _lease_expired_sec = 0;
	_lease_duration = 0xFFFFFFFFU;
	for (int i = T_RENEW; i <= T_LEASE_EXPIRED; i++)
	    _timers[i].unschedule();
    }

    if (const uint8_t *srvo = DHCPOptionUtil::fetch(p, DHO_DHCP_SERVER_IDENTIFIER, 4))
	_server_ip = IPAddress(srvo);
    else
	_server_ip = IPAddress();

    if (_lease_call)
	_lease_call->call_write(unparse_lease());
	
    // TODO: save it to a file !! using DriverManager!!?
}


void 
DHCPClient::push(int, Packet *p)
{
    const uint8_t *mtype = DHCPOptionUtil::fetch(p, DHO_DHCP_MESSAGE_TYPE, 1);
    const dhcpMessage *dm = reinterpret_cast<const dhcpMessage *>(p->transport_header() + sizeof(click_udp));

    if (!mtype || dm->xid != _curr_xid || dm->htype != ARPHRD_ETHER
	|| dm->hlen != 6 || memcmp(dm->chaddr, _ethAddr.data(), 6) != 0) {
	checked_output_push(2, p);
	return;
    }
    
    switch (*mtype) {

      case DHCP_OFFER:
	_timers[T_RESEND_DISCOVER].unschedule();
	if (!_timers[T_SELECT].scheduled())
	    _timers[T_SELECT].schedule_after(_select_interval);
	// enqueue it
	p->set_next(_offers);
	_offers = p;
	break;

      case DHCP_ACK:
	_state = DHCP_CLIENT_BOUND;
	_timers[T_TIMEOUT].unschedule();
	_timers[T_RESEND_REQUEST].unschedule();
	_curr_backoff = _initial_interval.sec();
	
	if (_best_offer) {
	    _best_offer->kill();
	    _best_offer = 0;
	}
	
	save_lease(p);
	p->kill();
	// TODO: ARP?
	// TODO: record the lease time duration.
	break;

      case DHCP_NACK:
	click_chatter("received DHCP_NACK!!");
	if (_state != DHCP_CLIENT_BOUND)
	    enter_init_state();
	p->kill();
	break;
	
      default:
	click_chatter("received an UNKNOWN DHCP MSG!!!!!");
	p->kill();
	break;
	
    }
}

void DHCPClient::choose_offer()
{
    if (_best_offer)
	_best_offer->kill();
    _best_offer = 0;

    // find the best offer for the chosen IP address
    Packet *best_overall_offer = 0;
    uint32_t best_ltime = 0;
    for (Packet *p = _offers; p; p = p->next())
	if (const uint8_t *o = DHCPOptionUtil::fetch(p, DHO_DHCP_LEASE_TIME, 4)) {
	    uint32_t ltime = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
	    if (!best_overall_offer || (!_best_offer && ltime > best_ltime)) {
		best_overall_offer = p;
		best_ltime = ltime;
	    }
	    const dhcpMessage *dm = reinterpret_cast<const dhcpMessage *>(p->transport_header() + sizeof(click_udp));
	    if (_my_ip && dm->yiaddr == _my_ip.addr()
		&& (!_best_offer || ltime > best_ltime)) {
		_best_offer = p;
		best_ltime = ltime;
	    }
	}

    if (!_best_offer)
	_best_offer = best_overall_offer;

    // delete all other offers 
    for (Packet *p = _offers; p; ) {
	Packet *n = p->next();
	if (p != _best_offer)
	    p->kill();
	p = n;
    }
    _offers = 0;
}

void DHCPClient::run_timer(Timer *t)
{
    switch (t - &_timers[0]) {

      case T_TIMEOUT:
	click_chatter("no DISCOVER_OFFER received");
	_timers[T_TIMEOUT].schedule_after(_timeout);
	/*_curr_retries++;
	  if(_curr_retries < _max_retries)
	  enter_init_state();
	  else
	  assert(0);*/
	break;

      case T_SELECT:
	click_chatter("[c] running select_timer()");
	choose_offer();
	click_chatter("[c] p : %p", _best_offer);
	if (_best_offer)
	    if (Packet *q = make_request(_best_offer)) {
		_state = DHCP_CLIENT_REQUESTING_STATE;
		_curr_backoff = _initial_interval.sec();
		_timers[T_RESEND_REQUEST].schedule_after_sec(DHCPOptionUtil::rand_exp_backoff(_curr_backoff));
		output(0).push(q);
	    }
	break;

      case T_RESEND_DISCOVER:
	click_chatter("sending DHCPDISCOVER");
	output(0).push(make_discovery());
	_timers[T_RESEND_DISCOVER].schedule_after_sec(6);
	if (_state == DHCP_CLIENT_INIT_STATE)
	    enter_selecting_state();
	break;
	
      case T_RESEND_REQUEST: {
	  Packet *q = make_request(_best_offer);
	  output(0).push(q);
	  
	  _curr_backoff = 2 * _curr_backoff;
	  if (_curr_backoff > _backoff_cutoff.sec())
	      _curr_backoff = _backoff_cutoff.sec();
	  _timers[T_RESEND_REQUEST].schedule_after_sec(DHCPOptionUtil::rand_exp_backoff(_curr_backoff));
	  break;
      }

      case T_RENEW:
	click_chatter("running renew timer");
	enter_renew_state();
	break;

      case T_REBIND:
	click_chatter("running rebind timer");
	enter_rebind_state();
	break;

      case T_LEASE_EXPIRED:
	click_chatter("CRAP!! lease expired!!!");
	_lease_duration = 0;
	enter_init_state();
	break;
  
    }
}

WritablePacket *DHCPClient::make_bootrequest(int mtype, uint32_t ciaddr, uint32_t xid)
{
    // will be followed by UDPIPEncap, so leave room
    WritablePacket *q = Packet::make(Packet::DEFAULT_HEADROOM + sizeof(click_ip) + sizeof(click_udp), 0, sizeof(dhcpMessage), 0);
    if (!q)
	return 0;

    dhcpMessage *dm = reinterpret_cast<dhcpMessage *>(q->data());
    memset(dm, 0, sizeof(dhcpMessage));
    dm->op = DHCP_BOOTREQUEST;
    dm->htype = ARPHRD_ETHER;
    dm->hlen = 6;
    dm->xid = xid;
    dm->ciaddr = ciaddr;
    memcpy(dm->chaddr, _ethAddr.data(), 6);
    dm->magic = DHCP_MAGIC;
    dm->options[0] = DHO_DHCP_MESSAGE_TYPE;
    dm->options[1] = 1;
    dm->options[2] = mtype;
    return q;
}

Packet *DHCPClient::make_request_with_ciaddr()
{
    WritablePacket *q = make_bootrequest(DHCP_REQUEST, _my_ip.addr(), click_random());
    if (!q)
	return 0;

    dhcpMessage *dm = reinterpret_cast<dhcpMessage *>(q->data());
    _curr_xid = dm->xid;
    dm->options[3] = DHO_END;
    q->take(DHCP_OPTIONS_SIZE - 4);
    return q;
}

Packet *DHCPClient::make_request(Packet *offer)
{
    const dhcpMessage *offer_dm = reinterpret_cast<const dhcpMessage *>(offer->transport_header() + sizeof(click_udp));
    WritablePacket *q = make_bootrequest(DHCP_REQUEST, 0, offer_dm->xid);
    if (!q)
	return 0;

    dhcpMessage *dm = reinterpret_cast<dhcpMessage *>(q->data());
    uint8_t *o = dm->options + 3;

    // requested ip address
    if (_state == DHCP_CLIENT_SELECTING_STATE
	|| _state == DHCP_CLIENT_INIT_REBOOT
	|| _state == DHCP_CLIENT_REBOOTING) {
	*o++ = DHO_DHCP_REQUESTED_ADDRESS;
	*o++ = 4;
	memcpy(o, &offer_dm->yiaddr, 4);
	o += 4;
    }
    
    // request lease time
    const uint8_t *leaseo = DHCPOptionUtil::fetch(offer, DHO_DHCP_LEASE_TIME, 4);
    if (!leaseo)  
	click_chatter("\tno lease time specified!!!!!!");
    else {
	*o++ = DHO_DHCP_LEASE_TIME;
	*o++ = 4;
	memcpy(o, leaseo, 4);
	o += 4;
    }
  
    // server identifier
    if (_state == DHCP_CLIENT_SELECTING_STATE)
	if (const uint8_t *servero = DHCPOptionUtil::fetch(offer, DHO_DHCP_SERVER_IDENTIFIER, 4)) {
	    *o++ = DHO_DHCP_SERVER_IDENTIFIER;
	    *o++ = 4;
	    memcpy(o, servero, 4);
	    o += 4;
	}

    *o++ = DHO_END;
    q->take(DHCP_OPTIONS_SIZE - (o - dm->options));
    return q;
}

Packet *DHCPClient::make_release()
{
    WritablePacket *q = make_bootrequest(DHCP_RELEASE, _my_ip.addr(), click_random());
    if (!q)
	return 0;
    
    dhcpMessage *dm = reinterpret_cast<dhcpMessage *>(q->data());
    _curr_xid = dm->xid;
    uint8_t *o = dm->options + 3;
    *o++ = DHO_DHCP_SERVER_IDENTIFIER;
    *o++ = 4;
    memcpy(o, _server_ip.data(), 4);
    o += 4;
    *o++ = DHO_END;
    q->take(DHCP_OPTIONS_SIZE - (o - dm->options));
    return q;
}

Packet *DHCPClient::make_discovery()
{
    WritablePacket *q = make_bootrequest(DHCP_DISCOVER, 0, click_random());
    if (!q)
	return 0;

    dhcpMessage *dm = reinterpret_cast<dhcpMessage *>(q->data());
    _curr_xid = dm->xid;
    uint8_t *o = dm->options + 3;
    if (_my_ip) {
	*o++ = DHO_DHCP_REQUESTED_ADDRESS;
	*o++ = 4;
	memcpy(o, _my_ip.data(), 4);
	o += 4;
    }
  
    if (_lease_duration > 0) {
	*o++ = DHO_DHCP_LEASE_TIME;
	*o++ = 4;
	uint32_t l = htonl(_lease_duration);
	memcpy(o, &l, 4);
	o += 4;
    }
    
    *o++ = DHO_END;
    q->take(DHCP_OPTIONS_SIZE - (o - dm->options));
    return q;
}

void
DHCPClient::send_dhcp_lease()
{
    Packet *q = make_release();
    output(1).push(q); //unicast;
}

Packet *
DHCPClient::make_deline()
{
  return NULL;
}

void 
DHCPClient::enter_init_state()
{
    _state = DHCP_CLIENT_INIT_STATE;
    //_retry_discover_timer.schedule_after_sec(15);
    for (int i = 0; i < NTIMERS; i++)
	_timers[i].unschedule();

    _t1_timestamp_sec  = 0;
    _t2_timestamp_sec  = 0;
    _lease_expired_sec = 0;
  
    _timers[T_TIMEOUT].schedule_after(_timeout);
    _timers[T_RESEND_DISCOVER].schedule_after_sec(click_random(0, 9));
}

void
DHCPClient::enter_init_reboot_state()
{
    click_chatter("[c] Enter INIT_REBOOT STATE");
    _timers[T_RESEND_DISCOVER].unschedule();

    Packet *q = make_request_with_ciaddr();
    output(0).push(q); // broadcast;
    _timers[T_LEASE_EXPIRED].schedule_after_sec(60);
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
DHCPClient::enter_renew_state()
{
    // send request via unicast
    // must not include server id
    Packet *q = make_request_with_ciaddr();
    output(1).push(q); // unicast;
  
    uint32_t next_timeout_sec = ( _t2_timestamp_sec - Timestamp::now().sec() ) / 2;
    if(next_timeout_sec > 60) 
	_timers[T_RENEW].schedule_after_sec(next_timeout_sec);
}


void 
DHCPClient::enter_rebind_state()
{
    Packet *q = make_request_with_ciaddr();
    output(0).push(q); //broadcast;
  
    uint32_t next_timeout_sec = ( _lease_expired_sec - Timestamp::now().sec() ) / 2;
    if(next_timeout_sec > 60)
	_timers[T_REBIND].schedule_after_sec(next_timeout_sec);
}

String DHCPClient::unparse_lease() const
{
    StringAccum sa;
    sa << cp_unparse_bool(_lease_duration) << " " << _my_ip;
    if (_lease_duration)
	sa << " " << _server_ip << " " << _start_timestamp_sec << " "
	   << _lease_expired_sec;
    return sa.take_string();
}

int DHCPClient::write_handler(const String &data_in, Element *e, void *thunk, ErrorHandler *errh)
{
    DHCPClient *dc = static_cast<DHCPClient *>(e);
    switch ((intptr_t) thunk) {
      case 0: {
	  String data = data_in;
	  String arg = cp_shift_spacevec(data);
	  bool lease_active;
	  IPAddress my_ip, server_ip;
	  uint32_t start_lease, end_lease;
	  if (!cp_bool(arg, &lease_active))
	      return errh->error("syntax error in lease format");
	  else if (!lease_active
		   && Args(dc, errh).push_back_words(data)
			.read_p("IP", my_ip)
			.complete() < 0)
	      return -1;
	  else if (lease_active
		   && Args(dc, errh).push_back_words(data)
		   .read_mp("IP", my_ip)
		   .read_mp("SERVERIP", server_ip)
		   .read_mp("START", SecondsArg(), start_lease)
		   .read_mp("END", SecondsArg(), end_lease)
		   .complete() < 0)
	      return -1;
	  if (!lease_active) {
	      dc->_lease_duration = 0;
	      dc->enter_init_state();
	  } else {
	      dc->_my_ip = my_ip;
	      dc->_server_ip = server_ip;
	      dc->_start_timestamp_sec = start_lease;
	      dc->_lease_expired_sec = end_lease;
	      dc->_lease_duration = end_lease - start_lease;
	      dc->enter_init_reboot_state();
	  }
	  return 0;
      }

      case 1:
	click_chatter("releasing lease");
	//release lease
	dc->send_dhcp_lease();
	return 0;

      default:
	return -1;

    }
}

String DHCPClient::read_handler(Element *e, void *thunk)
{
    DHCPClient *dc = static_cast<DHCPClient *>(e);
    switch ((intptr_t) thunk) {
      case 0:
	return dc->_my_ip.unparse();
      case 1:
	return dc->_server_ip.unparse();
      case 2:
	return dc->unparse_lease();
      default:
	return String();
    }
}

void
DHCPClient::add_handlers()
{
    add_read_handler("addr", read_handler, (void*)0);
    add_read_handler("server", read_handler, (void*)1);
    add_read_handler("lease", read_handler, (void*)2);
    add_write_handler("lease", write_handler, (void*)0);
    add_write_handler("release", write_handler, (void*)1);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DHCPClient)
ELEMENT_REQUIRES(DHCPOptionUtil)
