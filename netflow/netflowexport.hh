// -*- mode: c++; c-basic-offset: 2 -*-
#ifndef NETFLOWEXPORT_HH
#define NETFLOWEXPORT_HH

#include <click/element.hh>
#include <click/string.hh>
#include <click/timer.hh>
#include <click/notifier.hh>
#include "netflowpacket.hh"
#include "elements/analysis/aggregatenotifier.hh"
#include "netflowtemplatecache.hh"

CLICK_DECLS

/*
=c

NetflowExport(NOTIFIER, [I<KEYWORDS>])

=s Mazu Logging

generates Cisco NetFlow and IETF IPFIX records

=d

Generates Cisco NetFlow and IETF IPFIX records. Encapsulate in e.g.,
UDP to generate exportable packets.

NOTIFIER is the name of an AggregateNotifier element, like
AggregateIPFlows. NetflowExport uses the information provided by this
element to generate flow records.  Note that flow records are only generated
when the flows themselves expire, which can take some time.

Keyword arguments are:

=over 8

=item VERSION

Integer. Version of Netflow records to generate.

=item SOURCE_ID

(V9 and IPFIX only). Integer. Source identifier. Default is a random
number between 0 and 65535.

=item TEMPLATE_ID

(V9 and IPFIX only). Integer. Initial template identifier. Must be
greater than 255. Default is 1025.

=item INTERVAL

Number of seconds (millisecond precision).  If given, then generate flow
records every INTERVAL seconds, in addition to when flows are destroyed.
Default is 0 (do not generate interim flow records).

=item DEBUG

Boolean. Immediately generate flow records when a new flow is
detected. Default is false.

=back

=a

NetflowArrivalCounter, UnsummarizeNetflow */

class NetflowExport : public Element, public AggregateListener { 
public:

  NetflowExport();
  ~NetflowExport();
  
  const char *class_name() const	{ return "NetflowExport"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *flow_code() const		{ return "x/y"; }
  const char *processing() const	{ return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *errh);

  void aggregate_notify(uint32_t, AggregateEvent, const Packet *);
  Packet *simple_action(Packet *p);
  void run_timer(Timer *);

  uint16_t version() const { return _version; }
  uint32_t source_id() const { return _source_id; }
  uint32_t template_id() const { return _template_id; }
  uint32_t start() const { return _start.sec(); }

private:

  class Flow : public NetflowDataRecord {
  public:
    Flow(const Packet *p, NetflowExport *exporter, unsigned flow_sequence);
    ~Flow() {
    }

    template <class Header, class Record> void fill_record(NetflowExport *exporter, Record *r, Timestamp &now);
    void handle_packet(const Packet *p) { _packets++; _bytes += p->network_length(); }
    void send(NetflowExport *exporter);

    unsigned _flow_sequence;
    uint32_t _agg;

    Timestamp _start;	// flowStartSeconds

    // IPFIX mandates that packet and byte counters be 64-bit. Netflow
    // V9 specifies 32-bit counters by default but can support 64-bit
    // counters. Do the best we can.
#if HAVE_INT64_TYPES
    typedef uint64_t netflow_count_t;
#else
    typedef uint32_t netflow_count_t;
#endif
    netflow_count_t _packets;	// packetDeltaCount
    netflow_count_t _bytes;	// octetDeltaCount
  };

  // Configuration
  AggregateNotifier *_agg_notifier;
  uint16_t _version;
  uint32_t _source_id;
  uint16_t _template_id;
  bool _debug;

  Timestamp _start;
  HashTable<uint32_t, Flow *> _flows;
  unsigned _flow_sequence;

  Timer _timer;
  unsigned _interval;
};

CLICK_ENDDECLS
#endif
