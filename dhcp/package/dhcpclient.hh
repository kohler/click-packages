#ifndef DHCPCLIENT_HH
#define DHCPCLIENT_HH

#include "dhcp_common.hh"

#include <click/element.hh>
#include <click/timer.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

/*
 * =c
 * DHCPClient( etheraddress )
 *
 * =s DHCP
 * The core of the DHCP Client. The state machine resides in this element.
 *
 * =d 
 * DHCPClient has at least 3 outgoing ports. Port 0 is designated for
 * all broadcast packets. Port 1 is designated for all unicast
 * packets. Port 2 is designated for the DHCP_OFFER packets received
 * by the client.
 * 
 * There are 2 read handlers and 1 write handler.
 * client_write - write handler - For bootstrap purpose. It reads in
 * the client's information for a database, which is a flat file,
 * client.lease.
 *
 * client_ip_read - read handler - returns the client's currently bound IP.
 * 
 * server_ip_read - read handler - returns the server's IP.
 *
 * lease_read - read handler - returns the currently bound lease.
 *     Format: <client's IP>  <server's IP> <start time in secs> <end time in secs>
 * 
 * =e
 * DHCPClient(00:11:22:33:44);
 *
 * =a
 * DHCPUnicastEncap, DHCPOfferMsgQueue.
 *
 */

class DHCPClient : public Element
{
public:
  DHCPClient();
  ~DHCPClient();
  
  const char *class_name() const { return "DHCPClient"; }
  const char *port_count() const { return "2/3-4"; }
  const char *processing() const { return "hl/hhh"; }
  
  Packet* pull();
  void push(int port, Packet *p);
  //Packet* pull(int port);
  
  int initialize(ErrorHandler *);
  void add_handlers();
  int configure(Vector<String> &conf, ErrorHandler *errh);

  //void run_timer(Timer *);
  void run_resend_discover_timer();
  void run_timeout_timer();
  void run_select_timer();
  void run_resend_request_timer();
  void run_renew_timer();
  void run_rebind_timer();
  void run_lease_expired_timer();
  
  void set_my_ip(const String &ip);
  void set_server_ip(const String &ip);
  void set_my_lease_time(const int &time);
  const IPAddress& get_my_ip() const;
  const IPAddress& get_server_ip() const;
  const uint32_t get_my_lease_duration() const;
  const uint32_t get_my_lease_start_time() const;
  const uint32_t get_my_lease_end_time() const;
  
  void enter_init_state();
  void enter_init_reboot_state();
  void enter_rebooting_state();
  void enter_selecting_state();
  void enter_requesting_state();
  void enter_bound_state();
  void enter_renew_state();
  void enter_rebind_state();

  void save_lease(Packet *p);
  void send_dhcp_lease();

  bool _read_file;
private:
  
  Packet* make_discovery();
  Packet* make_request(Packet *p);
  Packet* make_request_with_ciaddr();
  Packet* make_release();
  Packet* make_deline();

  
  Packet* drop(Packet *p);
  
  Timestamp _timeout;			/* Start to panic if we don't get a
					   lease in this time period when
					   SELECTING. */
  Timestamp _initial_interval;		/* All exponential backoff intervals
					   start here. */
  Timestamp _retry_interval;		/* If the protocol failed to produce
					   an address before the timeout,
					   try the protocol again after this
					   many seconds. */
  Timestamp _select_interval;		/* Wait this many seconds from the
					   first DHCPDISCOVER before
					   picking an offered lease. */
  Timestamp _reboot_timeout;		/* When in INIT-REBOOT, wait this
					   long before giving up and going
					   to INIT. */
  Timestamp _backoff_cutoff;		/* When doing exponential backoff,
					   never back off to an interval
					   longer than this amount. */
  
    Timer _timeout_timer;
    Timer _select_timeout_timer;
    Timer _resend_discover_timer;
    Timer _resend_request_timer;
    Timer _renew_timer;
    Timer _rebind_timer;
    Timer _lease_expired_timer;

    int32_t _curr_backoff;
  
  dhcp_client_state_t _state; 
  uint32_t _curr_xid; 
  
  // lease info 
  EtherAddress _ethAddr;
  IPAddress _my_ip;
  IPAddress _server_ip;
  uint32_t _lease_duration;
  uint32_t _start_timestamp_sec;
  uint32_t _t1_timestamp_sec;
  uint32_t _t2_timestamp_sec;
  uint32_t _lease_expired_sec;
  
  // end lease info

  Packet* _chosen_offer_pkt;
  
};

CLICK_ENDDECLS
#endif

