// -*- c-basic-offset: 4 -*-
#ifndef CLICK_TCPMYSTERY_HH
#define CLICK_TCPMYSTERY_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <click/handlercall.hh>
#include "tcpcollector.hh"
#include "elements/analysis/aggregatenotifier.hh"
#include "elements/analysis/toipflowdumps.hh"
CLICK_DECLS
class ToIPSummaryDump;

/*
=c

TCPMystery([TRACEINFO, I<keywords> TRACEINFO, TRACEINFO_FILEPOS, TRACEINFO_TRACEFILE, NOTIFIER, FLOWDUMPS, SUMMARYDUMP, IP_ID, ACKLATENCY])

=s

analyzes TCP flows for loss events

=d

Expects TCP packets with aggregate annotations set as if by AggregateIPFlows.
Packets must have timestamps in increasing order. Analyzes these TCP flows and
figures out where the loss events are. Loss events may be reported to a
ToIPFlowDumps element, a ToIPSummaryDump element, and/or to a connection
information file.

Keywords are:

=over 8

=item TRACEINFO

Filename. If given, then output information about each aggregate to that file,
in an XML format. Information includes the flow identifier, total sequence
space used on each flow, and loss counts for each flow.

=item SOURCE

Element. If provided, the results of that element's 'C<filename>' and
'C<packet_filepos>' read handlers will be recorded in the TRACEINFO dump. (It
is not an error if the element doesn't have those handlers.) The
'C<packet_filepos>' results may be particularly useful, since a reader can use
those results to skip ahead through a trace file.

=item NOTIFIER

An AggregateNotifier element, such as AggregateIPFlows. CalculateTCPLossEvents
registers with the notifier to receive "delete aggregate" messages. It uses
these messages to delete state. If you don't provide a NOTIFIER,
CalculateTCPLossEvents will keep some state for every aggregate it sees until
the router quits.

=item FLOWDUMPS

A ToIPFlowDumps element. If provided, CalculateTCPLossEvents reports loss
events to that element; they will show up as comments like "C<#LOSSTYPE
DIRECTION TIME SEQ ENDTIME ENDSEQ>", where LOSSTYPE is "C<loss>" for loss
events, "C<ploss>" for possible loss events, or "C<floss>" for false loss
events, and DIRECTION is "C<E<gt>>" or "C<E<lt>>".

=item SUMMARYDUMP

A ToIPSummaryDump element. If provided, CalculateTCPLossEvents reports loss
events to that element; they will show up as comments like "C<#ALOSSTYPE
AGGREGATE DIRECTION TIME SEQ ENDTIME ENDSEQ>", where ALOSSTYPE is "C<aloss>"
for loss events, "C<aploss>" for possible loss events, or "C<afloss>" for
false loss events, and DIRECTION is "C<E<gt>>" or "C<E<lt>>".

=item IP_ID

Boolean. If true, then use IP ID to distinguish network duplicates from
retransmissions. Default is true.

=item ACKLATENCY

Boolean. If true, then output the latencies between data packets and their
acknowledgements to the TRACEINFO file. This information will be written
inside an "C<E<lt>acklatencyE<gt>>" XML element as a series of non-XML lines.
Each line has the format "I<timestamp> I<seq> I<latency>", where I<timestamp>
is the data packet's timestamp, I<seq> is its end sequence number, and
I<latency> is the delay between the packet's arrival and its ack's arrival at
the trace point. These lines will generally be sorted in increasing order of
I<timestamp>, but that is not guaranteed.

=item ACKCAUSALITY

Boolean. If true, then output the latencies between acknowledgements and the
packets to which they were responses to the TRACEINFO file. This information
will be written inside an "C<&lt;ackcausality&gt;>" XML element as a series of
non-XML lines.  Each line has the format "I<timestamp> I<ack> I<latency>",
where I<timestamp> is the data packet's timestamp, I<ack> is its
acknowledgement's sequence number, and I<latency> is the delay between the
packet's arrival and its ack's arrival at the trace point. These lines will
generally be sorted in increasing order of I<timestamp>, but that is not
guaranteed.

=item PACKET

Boolean.

=item REORDERED

Boolean.

=item FULLRCVWINDOW

Boolean. If true, then output a list of data packets that fill the receiver's
advertised window to the TRACEINFO file, inside a "C<E<lt>fullrcvwindowE<gt>>"
XML element. Each line has the format "I<timestamp> I<seq>", where
I<timestamp> is the packet's timestamp and I<seq> is its end sequence number.

=item UNDELIVERED

Boolean. If true, then output a list of data packets that did not appear to be
delivered to the receiver to the TRACEINFO file, inside a
"C<E<lt>undeliveredE<gt>>" XML element. Each line has the format "I<timestamp>
I<seq>", where I<timestamp> is the packet's timestamp and I<seq> is its end
sequence number.

=back

=e

   FromDump(-, STOP true, FORCE_IP true)
      -> IPClassifier(tcp)
      -> af :: AggregateIPFlows
      -> CalculateTCPLossEvents(NOTIFIER af, FLOWDUMPS flowd)
      -> flowd :: ToIPFlowDumps(/tmp/flow%04n, NOTIFIER af);

=a

AggregateIPFlows, ToIPFlowDumps */


class TCPMystery : public Element, public TCPCollector::AttachmentManager { public:

    TCPMystery();
    ~TCPMystery();

    const char *class_name() const	{ return "TCPMystery"; }

    int configure_phase() const		{ return ToIPFlowDumps::CONFIGURE_PHASE + 1; } // just after ToIPFlowDumps
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

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
    
  private:

    TCPCollector *_tcpc;
    int _myconn_offset;
    int _mypkt_offset;
    
    void find_min_ack_latency(Stream*, Conn*);
    void find_loss_events(Stream*, Conn*);
    
    static void mystery_loss_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_ackcausality_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_reordered_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_undelivered_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    
};


struct TCPMystery::MyPkt {
    enum Flags {
	F_REXMIT = 0x1,		// packet contains some retransmitted data
	F_FULL_REXMIT = 0x2,	// retransmitted data corresponds exactly
				// to an earlier packet
	F_EVENT_REXMIT = 0x4,	// packet closes a loss event
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
    struct timeval time;
    struct timeval end_time;

    bool unparse(StringAccum &, const MyStream *, const MyConn *, bool include_aggregate, bool absolute_time = true, bool absolute_seq = true) const;
    void unparse_xml(StringAccum &, const String &tagname) const;
};

struct TCPMystery::MyLossBlock {
    enum { CAPACITY = 32 };
    MyLossBlock *next;
    int n;
    MyLossInfo loss[CAPACITY];
    MyLossBlock(MyLossBlock *the_next)	: next(the_next), n(0) { }
    void write_xml(FILE *, const String &tagname) const;
};

struct TCPMystery::MyStream {
    bool have_ack_latency : 1;	// have we seen an ACK match?
    
    tcp_seq_t max_live_seq;	// maximum sequence number seen since last
				// loss event completed
    tcp_seq_t max_loss_seq;	// maximum sequence number seen in any loss
				// event
    
    uint32_t loss_events;	// number of loss events
    uint32_t false_loss_events;	// number of false loss events
    tcp_seq_t event_id;		// changes on each loss event

    struct timeval min_ack_latency; // minimum time between packet and ACK

    Pkt *acked_pkt_hint;	// hint to find_acked_pkt

    uint32_t nreordered;
    uint32_t nundelivered;
    
    // information about the most recent loss event
    MyLossInfo loss;		// most recent loss event
    MyLossBlock *loss_trail;	// previous loss events
    
    MyStream();
    ~MyStream();

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

struct TCPMystery::MyConn { public:
    
    MyConn();
    void kill(TCPMystery *);

    struct timeval rtt() const;
    MyStream &stream(int i)	{ assert(i==0||i==1); return _stream[i]; }
    const MyStream &stream(int i) const { assert(i==0||i==1); return _stream[i]; }

    void handle_packet(const Packet *, TCPMystery *);
    
    MyPkt *create_pkt(const Packet *, TCPMystery *);
    void calculate_loss_events(MyPkt *, unsigned dir, TCPMystery *);
    void post_update_state(const Packet *, MyPkt *, TCPMystery *);

    void finish(TCPMystery *);
    
  private:

    bool _finished : 1;		// have we finished the flow?
    MyStream _stream[2];
    
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
TCPMystery::mystream(Stream* stream, Conn* conn) const
{
    return &myconn(conn)->stream(stream->direction);
}




#if 0
class TCPMystery : public Element { public:

    TCPMystery();
    ~TCPMystery();

    const char *class_name() const	{ return "TCPMystery"; }

    int configure_phase() const		{ return ToIPFlowDumps::CONFIGURE_PHASE + 1; } // just after ToIPFlowDumps
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();
    
    Packet *simple_action(Packet *);

    typedef TCPCollector::Pkt Pkt;
    typedef TCPCollector::Conn Conn;
    struct MPkt;
    struct MStream;
    class MyConn;
    struct Loss;
    struct LossBlock;
    enum LossType { NO_LOSS, LOSS, POSSIBLE_LOSS, FALSE_LOSS };
    
    inline MPkt *mpkt(TCPCollector::Pkt *) const;
    inline MyConn *mconn(TCPCollector::Conn *) const;
    
    //ToIPFlowDumps *flow_dumps() const	{ return _tipfd; }
    //ToIPSummaryDump *summary_dump() const { return _tipsd; }

    enum { SAVE_UNDELIVERED_PACKETNO };
    int save(int what, uint32_t aggregate, int direction, const String &filename, ErrorHandler *);
    
  private:

    TCPCollector *_tcpc;
    int _mconn_offset;
    int _mpkt_offset;

    //ToIPFlowDumps *_tipfd;
    //ToIPSummaryDump *_tipsd;

    static void mystery_loss_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_ackcausality_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_reordered_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    static void mystery_undelivered_xmltag(FILE *f, TCPCollector::Stream &stream, TCPCollector::Conn &conn, const String &tagname, void *thunk);
    
    static int write_handler(const String &, Element *, void *, ErrorHandler*);
    
    friend class Conn;
    
};

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
    struct timeval time;
    struct timeval end_time;

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

    struct timeval min_ack_latency; // minimum time between packet and ACK

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

    struct timeval rtt() const;
    MyStream &stream(int i)	{ assert(i==0||i==1); return _stream[i]; }
    const MyStream &stream(int i) const { assert(i==0||i==1); return _stream[i]; }

    void handle_packet(const Packet *, TCPMystery *);
    
    MPkt *create_pkt(const Packet *, TCPMystery *);
    void calculate_loss_events(MPkt *, unsigned dir, TCPMystery *);
    void post_update_state(const Packet *, MPkt *, TCPMystery *);

    void finish(TCPMystery *);
    
  private:

    bool _finished : 1;		// have we finished the flow?
    MyStream _stream[2];
    
};
#endif

CLICK_ENDDECLS
#endif
