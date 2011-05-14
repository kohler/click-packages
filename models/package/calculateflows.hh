// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/handlercall.hh>
#include <click/dequeue.hh>
#include "elements/analysis/aggregatenotifier.hh"
#include "elements/analysis/toipflowdumps.hh"
CLICK_DECLS
class ToIPSummaryDump;

/*
=c

CalculateTCPLossEvents([TRACEINFO, I<keywords> TRACEINFO, TRACEINFO_FILEPOS, TRACEINFO_TRACEFILE, NOTIFIER, FLOWDUMPS, SUMMARYDUMP, IP_ID, ACKLATENCY])

=s ipmeasure

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

class CalculateFlows : public Element, public AggregateListener { public:

    CalculateFlows();
    ~CalculateFlows();

    const char *class_name() const	{ return "CalculateTCPLossEvents"; }
    const char *port_count() const	{ return "1/1-2"; }
    const char *processing() const	{ return "a/ah"; }

    int configure_phase() const		{ return ToIPFlowDumps::CONFIGURE_PHASE + 1; } // just after ToIPFlowDumps
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

    void aggregate_notify(uint32_t, AggregateEvent, const Packet *packet);

    Packet *simple_action(Packet *);

    struct StreamInfo;
    class ConnInfo;
    struct LossInfo;
    struct LossBlock;
    struct Pkt;
    enum LossType { NO_LOSS, LOSS, POSSIBLE_LOSS, FALSE_LOSS };

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    ToIPFlowDumps *flow_dumps() const	{ return _tipfd; }
    ToIPSummaryDump *summary_dump() const { return _tipsd; }
    FILE *traceinfo_file() const	{ return _traceinfo_file; }
    HandlerCall *filepos_h() const	{ return _filepos_h; }

    enum WriteFlags { WR_ACKLATENCY = 1, WR_ACKCAUSALITY = 2, WR_FULLRCVWND = 4, WR_UNDELIVERED = 8, WR_WINDOWPROBE = 16, WR_PACKETS = 32, WR_REORDERED = 64 };
    WriteFlags write_flags() const	{ return (WriteFlags)_write_flags; }

    enum { SAVE_UNDELIVERED_PACKETNO };
    int save(int what, uint32_t aggregate, int direction, const String &filename, ErrorHandler *);

    typedef HashTable<unsigned, ConnInfo *> ConnMap;

  private:

    ConnMap _conn_map;

    ToIPFlowDumps *_tipfd;
    ToIPSummaryDump *_tipsd;
    FILE *_traceinfo_file;
    HandlerCall *_filepos_h;

    bool _ip_id : 1;

    Pkt *_free_pkt;
    Vector<Pkt *> _pkt_bank;

    String _traceinfo_filename;
    Element *_packet_source;
    int _write_flags;

    Pkt *new_pkt();
    inline void free_pkt(Pkt *);
    inline void free_pkt_list(Pkt *, Pkt *);

    static int write_handler(const String &, Element *, void *, ErrorHandler*);

    friend class ConnInfo;

};

struct CalculateFlows::Pkt {
    Pkt *next;
    Pkt *prev;

    uint32_t data_packetno;	// data packet number of this packet
    tcp_seq_t seq;		// sequence number of this packet
    tcp_seq_t end_seq;		// end sequence number of this packet
    tcp_seq_t ack;		// ack sequence number of this packet
    Timestamp timestamp;	// timestamp of this packet
    uint32_t packetno_anno;	// packet number annotation of this packet
    uint16_t ip_id;		// IP ID of this packet

    enum Flags {
	F_NEW = 0x1,		// packet contains some new data
	F_REXMIT = 0x2,		// packet contains some retransmitted data
	F_FULL_REXMIT = 0x4,	// retransmitted data corresponds exactly
				// to an earlier packet
	F_EVENT_REXMIT = 0x8,	// packet closes a loss event
	F_DUPLICATE = 0x10,	// packet is a network duplicate
	F_REORDER = 0x20,	// packet is reordered
	F_NONORDERED = 0x40,	// packet is part of a non-ordered block
				// (retransmission or reordering)
	F_KEEPALIVE = 0x80,	// packet is a keepalive
	F_ACK_REORDER = 0x100,	// packet's ackno is reordered
	F_ACK_NONORDERED = 0x200, // packet is part of a non-ordered ack block

	F_FILLS_RCV_WINDOW = 0x400, // packet filled receive window
	F_WINDOW_PROBE = 0x800,	// packet was a window probe

	F_DELIVERED = 0x10000,	// do we think the packet was delivered?
    };
    int flags;			// packet flags

    tcp_seq_t event_id;		// ID of loss event

    Pkt *caused_ack;		// ack that this data packet caused
};

struct CalculateFlows::LossInfo {
    LossType type;
    uint32_t data_packetno;
    uint32_t end_data_packetno;
    tcp_seq_t seq;
    tcp_seq_t top_seq;
    Timestamp time;
    Timestamp end_time;

    bool unparse(StringAccum &, const StreamInfo *, const ConnInfo *, bool include_aggregate, bool absolute_time = true, bool absolute_seq = true) const;
    void unparse_xml(StringAccum &) const;
};

struct CalculateFlows::LossBlock {
    enum { CAPACITY = 32 };
    LossBlock *next;
    int n;
    LossInfo loss[CAPACITY];

    LossBlock(LossBlock *the_next)	: next(the_next), n(0) { }
    void write_xml(FILE *) const;
};

struct CalculateFlows::StreamInfo {
    unsigned direction : 1;	// our direction
    bool have_init_seq : 1;	// have we seen a sequence number yet?
    bool have_syn : 1;		// have we seen a SYN?
    bool different_syn : 1;	// did we see a different SYN?
    bool have_fin : 1;		// have we seen a FIN?
    bool different_fin : 1;	// did we see a different FIN?
    bool have_ack_latency : 1;	// have we seen an ACK match?
    bool filled_rcv_window : 1;	// have we ever filled the receive window?
    bool sent_window_probe : 1;	// have we ever sent a window probe?
    bool sent_sackok : 1;	// did we send SACKOK on the SYN?
    bool time_confusion : 1;	// was there timestamp confusion?

    tcp_seq_t init_seq;		// first absolute sequence number seen, if any
				// all other sequence numbers are relative

    tcp_seq_t syn_seq;		// sequence number of SYN, if any
    tcp_seq_t fin_seq;		// sequence number of FIN, if any

    tcp_seq_t max_seq;		// maximum sequence number seen on connection
    tcp_seq_t max_ack;		// maximum sequence number acknowledged

    tcp_seq_t max_live_seq;	// maximum sequence number seen since last
				// loss event completed
    tcp_seq_t max_loss_seq;	// maximum sequence number seen in any loss
				// event

    uint32_t total_packets;	// total number of packets seen (incl. rexmits)
    uint32_t ack_packets;	// total number of pure acks seen
    uint32_t total_seq;		// total sequence space seen (incl. rexmits)

    uint32_t loss_events;	// number of loss events
    uint32_t false_loss_events;	// number of false loss events
    tcp_seq_t event_id;		// changes on each loss event

    Timestamp min_ack_latency;	// minimum time between packet and ACK

    tcp_seq_t end_rcv_window;	// end of receive window
    int rcv_window_scale;	// window scaling option

    Pkt *pkt_head;		// first packet record
    Pkt *pkt_tail;		// last packet record
    Pkt *pkt_data_tail;		// last packet record with data

    Pkt *acked_pkt_hint;	// hint to find_acked_pkt

    // information about the most recent loss event
    LossInfo loss;		// most recent loss event
    LossBlock *loss_trail;	// previous loss events

    StreamInfo();
    ~StreamInfo();

    void categorize(Pkt *insertion, ConnInfo *, CalculateFlows *);
    void register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *, CalculateFlows *);
    void update_counters(const Pkt *np, const click_tcp *);
    void options(Pkt *np, const click_tcp *, int transport_length, const ConnInfo *);

    Pkt *find_acked_pkt(const Pkt *ackk, Pkt *search_hint = 0) const;
#if 0
    Pkt *find_ack_cause(const Pkt *ackk, Pkt *search_hint = 0) const;
#endif
    Pkt *find_ack_cause2(const Pkt *ackk, Pkt *&k, tcp_seq_t &) const;

    bool mark_delivered(const Pkt *ackk, Pkt *&k_cumack, Pkt *&k_time, tcp_seq_t prev_ackno, int prev_ndupack) const;

    void finish(ConnInfo*, CalculateFlows*);
    void unfinish();

    void output_loss(ConnInfo *, CalculateFlows *);
    void write_xml(ConnInfo *, FILE *, WriteFlags) const;
    void write_ack_latency_xml(ConnInfo *, FILE *) const;
    void write_ack_causality_xml(ConnInfo *, FILE *) const;
    void write_reordered_xml(FILE *, WriteFlags, int n) const;
    void write_full_rcv_window_xml(FILE *) const;
    void write_window_probe_xml(FILE *) const;
    void write_undelivered_xml(FILE *, WriteFlags, int n) const;
    void write_packets_xml(FILE *) const;

};

class CalculateFlows::ConnInfo {  public:

    ConnInfo(const Packet *, const HandlerCall *);
    void kill(CalculateFlows *);

    uint32_t aggregate() const		{ return _aggregate; }
    const Timestamp &init_time() const	{ return _init_time; }
    Timestamp rtt() const;
    const StreamInfo *stream(int i) const { assert(i==0||i==1); return &_stream[i]; }

    void handle_packet(const Packet *, CalculateFlows *);

    Pkt *create_pkt(const Packet *, CalculateFlows *);
    void calculate_loss_events(Pkt *, unsigned dir, CalculateFlows *);
    void post_update_state(const Packet *, Pkt *, CalculateFlows *);

    void finish(CalculateFlows *);

  private:

    uint32_t _aggregate;	// aggregate number
    IPFlowID _flowid;		// flow identifier for _stream[0]
    Timestamp _init_time;	// first time seen in stream
    String _filepos;		// file position of first packet
    bool _finished : 1;		// have we finished the flow?
    bool _clean : 1;		// have packets been added since we finished?
    StreamInfo _stream[2];

};

inline uint32_t
CalculateFlows::calculate_seqlen(const click_ip *iph, const click_tcp *tcph)
{
    return (ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2)) + (tcph->th_flags & TH_SYN ? 1 : 0) + (tcph->th_flags & TH_FIN ? 1 : 0);
}

inline void
CalculateFlows::free_pkt(Pkt *p)
{
    if (p) {
	p->next = _free_pkt;
	_free_pkt = p;
    }
}

inline void
CalculateFlows::free_pkt_list(Pkt *head, Pkt *tail)
{
    if (head) {
	tail->next = _free_pkt;
	_free_pkt = head;
    }
}

CLICK_ENDDECLS
#endif
