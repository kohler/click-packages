// -*- c-basic-offset: 4 -*-
#ifndef CLICK_TCPMYSTERY_HH
#define CLICK_TCPMYSTERY_HH
#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/handlercall.hh>
#include "tcpcollector.hh"
#include "elements/analysis/aggregatenotifier.hh"
CLICK_DECLS

/*
=c

TCPMystery(TCPCOLLECTOR [, I<keywords> RTT, SEMIRTT, ACKCAUSATION])

=s ipmeasure

analyzes TCP flows

=io

None

=d

Analyzes TCP flows and dumps various flow information to an XML trace info
file.  Both the flows and the trace info file are handled through a
TCPCollector collector element elsewhere in the connection; TCPMystery itself
has no inputs or outputs.

Keywords are:

=over 8

=item RTT

Boolean.  If true (the default), then write information about each TCP flow's
RTT to the trace info file.  Several "C<E<lt>rttE<gt>>" XML tags are written,
indicating the RTT from the syn-synack-ack exchange (if this could be
calculated); the minimum RTT; the average RTT; and the maximum RTT.  You can
tell these apart by looking at the "C<source>" attribute.  The actual RTT in
seconds is stored in the "C<value>" attribute.  For example:

  <rtt source='syn' value='0.083388' />
  <rtt source='min' value='0.082697' />
  <rtt source='avg' value='0.0932847' />
  <rtt source='max' value='0.116549' />

=item SEMIRTT

Boolean.  If true, then write information about each stream's semi-RTTs to the
trace info file in "C<E<lt>semirttE<gt>>" tags.  Default is false.  A semi-RTT
is the length of time between the observation of a data packet, and the
observation of the acknowledgement liberated by that data packet.  The
"C<E<lt>semirttE<gt>>" tags are like the "C<E<lt>rttE<gt>>" tags printed for
the whole connection, but there may be an additional entry containing a
bias-corrected sample variance for the semi-RTT measurements
E<lparen>"C<source='var'>").  For example:

  <semirtt source='syn' value='0.083183' />
  <semirtt source='min' value='0.082529' />
  <semirtt source='avg' value='0.089544' n='71' />
  <semirtt source='max' value='0.1057' />
  <semirtt source='var' value='2.07997e-05' n='71' />

=item ACKCAUSATION

Boolean.  If true, then write information about individual semi-RTTs to the
trace info file in "C<E<lt>ackcausationE<gt>>" tags.  Default is false.

=item UNDELIVERED

Boolean.  If true, then write information about any undelivered data packets
to the trace info file in "C<E<lt>undeliveredE<gt>>" tags.  Default is false.

=back

=e

   f :: FromDump(-, STOP true, FORCE_IP true)
      -> IPClassifier(tcp)
      -> af :: AggregateIPFlows
      -> tcol :: TCPCollector(-, SOURCE f, NOTIFIER af)
      -> TCPMystery(tcol, SEMIRTT true)
      -> Discard;

=a

TCPCollector, MultiQ */


class TCPMystery : public Element, public TCPCollector::AttachmentManager { public:

    TCPMystery();
    ~TCPMystery();

    const char *class_name() const	{ return "TCPMystery"; }
    const char *port_count() const	{ return "1/1-2"; }

    int configure(Vector<String> &, ErrorHandler *);

    typedef TCPCollector::Pkt Pkt;
    typedef TCPCollector::Stream Stream;
    typedef TCPCollector::Conn Conn;

    struct MyLossInfo;
    struct MyLossBlock;
    struct MyStream;
    struct MyConn;
    struct MyPkt;
    enum MyLossType { NO_LOSS, LOSS, POSSIBLE_LOSS, FALSE_LOSS };

    inline MyPkt* mypkt(Pkt*) const;
    inline MyStream* mystream(Stream*, Conn*) const;
    inline MyConn* myconn(Conn*) const;

    void new_conn_hook(Conn*, unsigned);

  private:

    TCPCollector *_tcpc;
    int _myconn_offset;
    int _mypkt_offset;

    void clear_mypkts(Stream*, Conn*);
    void find_true_caused_acks(Stream*, Conn*);
    void calculate_semirtt(Stream*, Conn*);
    void find_delivered(Stream*, Conn*);

    static void mystery_rtt_xmltag(FILE* f, TCPCollector::Conn* conn, const String& tagname, void* thunk);
    static void mystery_semirtt_xmltag(FILE* f, TCPCollector::Stream* stream, TCPCollector::Conn* conn, const String& tagname, void* thunk);
    static void mystery_ackcausation_xmltag(FILE* f, TCPCollector::Stream* stream, TCPCollector::Conn* conn, const String& tagname, void* thunk);
    static void mystery_undelivered_xmltag(FILE* f, TCPCollector::Stream* stream, TCPCollector::Conn* conn, const String& tagname, void* thunk);

    void find_min_ack_latency(Stream*, Conn*);
    void find_loss_events(Stream*, Conn*);

    static void mystery_loss_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_reordered_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);

};


struct TCPMystery::MyPkt {
    enum Flags {
	F_TRUE_CAUSED_ACK = 0x1, // packet's caused ack is definitely true
	F_REXMIT = 0x2,		// packet contains some retransmitted data
	F_FULL_REXMIT = 0x4,	// retransmitted data corresponds exactly
				// to an earlier packet
	F_EVENT_REXMIT = 0x8,	// packet closes a loss event
	F_DELIVERED = 0x10	// do we think the packet was delivered?
    };
    int flags;			// packet flags
    tcp_seq_t event_id;		// ID of loss event
    TCPCollector::Pkt* rexmit;	// closest packet to the original transmission
    TCPCollector::Pkt* caused_ack; // ack that this data packet caused
};

struct TCPMystery::MyLossInfo {
    MyLossType type;
    uint32_t data_packetno;
    uint32_t end_data_packetno;
    tcp_seq_t seq;
    tcp_seq_t top_seq;
    Timestamp time;
    Timestamp end_time;

    bool unparse(StringAccum &, const MyStream *, const MyConn *, bool include_aggregate, bool absolute_time = true, bool absolute_seq = true) const;
    void unparse_xml(StringAccum &, const String &tagname) const;
};

struct TCPMystery::MyLossBlock {
    enum { CAPACITY = 32 };
    MyLossBlock* next;
    int n;
    MyLossInfo loss[CAPACITY];
    MyLossBlock(MyLossBlock* the_next)	: next(the_next), n(0) { }
    void write_xml(FILE*, const String& tagname) const;
};

struct TCPMystery::MyStream {
    enum {
	F_CLEARPKTS = 1, F_TRUEACKCAUSATION = 2, F_SEMIRTT = 4,
	F_DELIVERED = 8
    };
    int flags;
    double semirtt_min;
    double semirtt_syn;
    double semirtt_max;
    double semirtt_sum;
    double semirtt_sumsq;
    int nsemirtt;
};

struct TCPMystery::MyConn {
    MyStream* mystream(int i)	{ assert(i==0||i==1); return &_stream[i]; }
    const MyStream* mystream(int i) const { assert(i==0||i==1); return &_stream[i]; }
  private:
    MyStream _stream[2];
    friend class TCPMystery;
};

inline TCPMystery::MyPkt*
TCPMystery::mypkt(Pkt* pkt) const
{
    return reinterpret_cast<MyPkt *>(reinterpret_cast<char *>(pkt) + _mypkt_offset);
}

inline TCPMystery::MyConn*
TCPMystery::myconn(Conn* conn) const
{
    return reinterpret_cast<MyConn *>(reinterpret_cast<char *>(conn) + _myconn_offset);
}

inline TCPMystery::MyStream*
TCPMystery::mystream(Stream* s, Conn* conn) const
{
    return myconn(conn)->mystream(s->direction);
}


#if 0

struct TCPMystery::MPkt {
    enum Flags {
	F_REXMIT = 0x1,		// packet contains some retransmitted data
	F_FULL_REXMIT = 0x2,	// retransmitted data corresponds exactly
				// to an earlier packet
	F_EVENT_REXMIT = 0x4,	// packet closes a loss event
	F_REORDER = 0x8,	// packet is reordered
	F_DELIVERED = 0x10	// do we think the packet was delivered?
    };
    int flags;			// packet flags
    tcp_seq_t event_id;		// ID of loss event
    TCPCollector::Pkt *caused_ack; // ack that this data packet caused
};

struct TCPMystery::Loss {
    LossType type;
    uint32_t data_packetno;
    uint32_t end_data_packetno;
    tcp_seq_t seq;
    tcp_seq_t top_seq;
    Timestamp time;
    Timestamp end_time;

    bool unparse(StringAccum &, const MStream *, const MyConn *, bool include_aggregate, bool absolute_time = true, bool absolute_seq = true) const;
    void unparse_xml(StringAccum &, const String &tagname) const;
};

struct TCPMystery::LossBlock {
    enum { CAPACITY = 32 };
    LossBlock *next;
    int n;
    Loss loss[CAPACITY];
    LossBlock(LossBlock *the_next)	: next(the_next), n(0) { }
    void write_xml(FILE *, const String &tagname) const;
};

struct TCPMystery::MStream {
    bool have_ack_latency : 1;	// have we seen an ACK match?

    tcp_seq_t max_live_seq;	// maximum sequence number seen since last
				// loss event completed
    tcp_seq_t max_loss_seq;	// maximum sequence number seen in any loss
				// event

    uint32_t loss_events;	// number of loss events
    uint32_t false_loss_events;	// number of false loss events
    tcp_seq_t event_id;		// changes on each loss event

    Timestamp min_ack_latency;	// minimum time between packet and ACK

    TCPCollector::Pkt *acked_pkt_hint;	// hint to find_acked_pkt

    uint32_t nreordered;
    uint32_t nundelivered;

    // information about the most recent loss event
    Loss loss;		// most recent loss event
    LossBlock *loss_trail;	// previous loss events

    MStream();
    ~MStream();

    void categorize(TCPCollector::Pkt *insertion, MyConn *, TCPMystery *);
    void register_loss_event(TCPCollector::Pkt *startk, TCPCollector::Pkt *endk, TCPCollector::Conn *, TCPMystery *);
    void update_counters(const TCPCollector::Pkt *np, const click_tcp *);
    void options(TCPCollector::Pkt *np, const click_tcp *, int transport_length, const TCPCollector::Conn *);

    TCPCollector::Pkt *find_acked_pkt(const TCPCollector::Pkt *ackk, TCPCollector::Pkt *search_hint = 0) const;
#if 0
    Pkt *find_ack_cause(const Pkt *ackk, Pkt *search_hint = 0) const;
#endif
    TCPCollector::Pkt *find_ack_cause2(const TCPCollector::Pkt *ackk, TCPCollector::Pkt *&k, tcp_seq_t &) const;

    bool mark_delivered(const TCPCollector::Pkt *ackk, TCPCollector::Pkt *&k_cumack, TCPCollector::Pkt *&k_time, tcp_seq_t prev_ackno, int prev_ndupack) const;

    void finish(TCPCollector::Conn*, TCPMystery*);
    void unfinish();

    void output_loss(TCPCollector::Conn *, TCPMystery *);
    void write_xml(TCPCollector::Conn *, FILE *) const;

};

class TCPMystery::MyConn {  public:

    MyConn();
    void kill(TCPMystery *);

    MyStream &stream(int i)	{ assert(i==0||i==1); return _stream[i]; }
    const MyStream &stream(int i) const { assert(i==0||i==1); return _stream[i]; }

    void finish_ackcausation(TCPMystery *);
    void finish_rtt(TCPMystery *);
    void finish_undelivered(TCPMystery *);

  private:

    bool _cleared : 1;
    bool _have_ackcausation : 1;
    bool _have_undelivered : 1;
    MyStream _stream[2];

};
#endif

CLICK_ENDDECLS
#endif
