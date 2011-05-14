#ifndef DHCPCLIENT_HH
#define DHCPCLIENT_HH
#include "dhcp_common.hh"
#include <click/element.hh>
#include <click/timer.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
CLICK_DECLS
class HandlerCall;

/*
=c

DHCPClient(ETH [, I<keywords>])

=s DHCP

The core of the DHCP Client. The state machine resides in this element.

=d

DHCPClient has at least 2 outgoing ports. Port 0 is designated for all
broadcast packets. Port 1 is designated for all unicast packets. Invalid
packets are output on port 2, if it exists; otherwise they are dropped.

Keyword arguments are:

=over 8

=item IP

The client's current IP address, if any.

=item LEASE_CALL

A write handler to be called when the client gets a new lease, or loses its
current lease.  The write handler is called with additional arguments
consisting of the new lease description (see the 'lease' handler below).

=back

=h addr read-only

Returns the client's current IP address.

=h server read-only

Returns the server's current IP address.

=h lease read/write

The read handler returns information about the currently active DHCP lease.
If a lease is active, the format is C<"true MYIP SRVIP START END">, where MYIP
is the client's current IP address, SRVIP is the server's current IP address,
and START and END are times in seconds.  If no lease is active, the format is
C<"false MYIP">, where MYIP is the client's most recently active IP address.

The write handler expects a string in the same format, and sets the current
lease accordingly.

=h release write-only

When written, releases the currently active DHCP lease, if any.

=e

  dhcpc :: DHCPClient(00:11:22:33:44, LEASE_CALL newlease.run)
	-> UDPIPEncap(0.0.0.0, bootpc, 255.255.255.255, bootps)
	-> ...;
  dhcpc[1] -> dhcp_udp :: UDPIPEncap(0.0.0.0, bootpc, 255.255.255.255, bootps)
	-> ...;
  newlease :: Script(TYPE PASSIVE,
  	goto end $(not $1),
	write dhcp_udp.src $2,
	write dhcp_udp.dst $3);

*/

class DHCPClient : public Element
{
public:
    DHCPClient();
    ~DHCPClient();

    const char *class_name() const { return "DHCPClient"; }
    const char *port_count() const { return "1/2-3"; }
    const char *processing() const { return PUSH; }

    void push(int port, Packet *p);

    int initialize(ErrorHandler *);
    void add_handlers();
    int configure(Vector<String> &conf, ErrorHandler *errh);
    void cleanup(CleanupStage);

    void run_timer(Timer *);

    String unparse_lease() const;

  void enter_init_state();
  void enter_init_reboot_state();
  void enter_rebooting_state();
  void enter_selecting_state();
  void enter_renew_state();
  void enter_rebind_state();

  void send_dhcp_lease();

private:

  Packet* make_discovery();
  Packet* make_request(Packet *p);
  Packet* make_request_with_ciaddr();
  Packet* make_release();
  Packet* make_deline();

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

    // order is important:
    enum { T_TIMEOUT, T_SELECT, T_RESEND_DISCOVER,
	   T_RESEND_REQUEST, T_RENEW, T_REBIND, T_LEASE_EXPIRED, NTIMERS };
    Timer _timers[NTIMERS];

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

    Packet *_offers;
    Packet *_best_offer;

    HandlerCall *_lease_call;

    WritablePacket *make_bootrequest(int mtype, uint32_t ciaddr, uint32_t xid);
    void choose_offer();
    void save_lease(Packet *p);
    static String read_handler(Element *, void *);
    static int write_handler(const String &, Element *, void *, ErrorHandler *);

};

CLICK_ENDDECLS
#endif
