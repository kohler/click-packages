// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <click/handlercall.hh>
#include "elements/analysis/aggregatenotifier.hh"
#include "elements/analysis/toipflowdumps.hh"
CLICK_DECLS
class ToIPSummaryDump;

/*
=c

CalculateTCPLossEvents([TRACEINFO, I<keywords> TRACEINFO, TRACEINFO_FILEPOS, TRACEINFO_TRACEFILE, NOTIFIER, FLOWDUMPS, SUMMARYDUMP, IP_ID, ACK_MATCH])

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
events, and DIRECTION is "C<&gt;>" or "C<&lt;>".

=item SUMMARYDUMP

A ToIPSummaryDump element. If provided, CalculateTCPLossEvents reports loss
events to that element; they will show up as comments like "C<#ALOSSTYPE
AGGREGATE DIRECTION TIME SEQ ENDTIME ENDSEQ>", where ALOSSTYPE is "C<aloss>"
for loss events, "C<aploss>" for possible loss events, or "C<afloss>" for
false loss events, and DIRECTION is "C<&gt;>" or "C<&lt;>".

=item IP_ID

Boolean. If true, then use IP ID to distinguish network duplicates from
retransmissions. Default is true.

=item ACK_MATCH

Boolean. If true, then output comments about which packet each ACK matches to
the FLOWDUMPS element. Default is false.

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
    const char *processing() const	{ return "a/ah"; }
    CalculateFlows *clone() const	{ return new CalculateFlows; }

    void notify_noutputs(int);
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
    bool ack_match() const		{ return _ack_match; }

    static double float_timeval(const struct timeval &);
    
    typedef BigHashMap<unsigned, ConnInfo *> ConnMap;
    
  private:
    
    ConnMap _conn_map;

    ToIPFlowDumps *_tipfd;
    ToIPSummaryDump *_tipsd;
    FILE *_traceinfo_file;
    HandlerCall *_filepos_h;

    bool _ack_match : 1;
    bool _ip_id : 1;
    
    Pkt *_free_pkt;
    Vector<Pkt *> _pkt_bank;

    String _traceinfo_filename;
    Element *_packet_source;

    Pkt *new_pkt();
    inline void free_pkt(Pkt *);
    inline void free_pkt_list(Pkt *, Pkt *);

    static int write_handler(const String &, Element *, void *, ErrorHandler*);
    
    friend class ConnInfo;
    
};

struct CalculateFlows::Pkt {
    Pkt *next;
    Pkt *prev;

    tcp_seq_t seq;		// sequence number of this packet
    tcp_seq_t last_seq;		// last sequence number of this packet
    tcp_seq_t ack;		// ack sequence number of this packet
    struct timeval timestamp;	// timestamp of this packet
    uint16_t ip_id;		// IP ID of this packet

    enum Flags { F_NEW = 1, F_REXMIT = 2, F_DUPLICATE = 4, F_REORDER = 8, F_STRANGE = 16, F_PARTIAL_REXMIT = 32, F_KEEPALIVE = 64 };
    int flags;			// packet flags

    tcp_seq_t event_id;		// ID of loss event
};

struct CalculateFlows::LossInfo {
    LossType type;
    tcp_seq_t seq;
    tcp_seq_t last_seq;
    struct timeval time;
    struct timeval end_time;

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
    bool have_fin : 1;		// have we seen a FIN?
    bool have_ack_bounce : 1;	// have we seen an ACK bounce?
    
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
    uint32_t total_seq;		// total sequence space seen (incl. rexmits)
    
    uint32_t loss_events;	// number of loss events
    uint32_t possible_loss_events; // number of possible loss events
    uint32_t false_loss_events;	// number of false loss events
    tcp_seq_t event_id;		// changes on each loss event

    struct timeval min_ack_bounce; // minimum time between packet and ACK

    Pkt *pkt_head;		// first packet record
    Pkt *pkt_tail;		// last packet record

    // information about the most recent loss event
    LossInfo loss;		// most recent loss event
    LossBlock *loss_trail;	// previous loss events
    
    StreamInfo();
    ~StreamInfo();

    void categorize(Pkt *insertion, ConnInfo *, CalculateFlows *);
    void register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *, CalculateFlows *);
    void update_counters(const Pkt *np, const click_tcp *, const ConnInfo *);
    
    Pkt *find_acked_pkt(tcp_seq_t, const struct timeval &);

    void output_loss(ConnInfo *, CalculateFlows *);
    void write_xml(FILE *) const;
    
};

class CalculateFlows::ConnInfo {  public:
    
    ConnInfo(const Packet *, const HandlerCall *);
    void kill(CalculateFlows *);

    uint32_t aggregate() const		{ return _aggregate; }
    const struct timeval &init_time() const { return _init_time; }

    void handle_packet(const Packet *, CalculateFlows *);
    
    Pkt *create_pkt(const Packet *, CalculateFlows *);
    void calculate_loss_events(Pkt *, unsigned dir, CalculateFlows *);
    void post_update_state(const Packet *, Pkt *, CalculateFlows *);
    
  private:

    uint32_t _aggregate;	// aggregate number
    IPFlowID _flowid;		// flow identifier for _stream[0]
    struct timeval _init_time;	// first time seen in stream
    String _filepos;		// file position of first packet
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

inline struct timeval
operator*(double frac, const struct timeval &tv)
{
    double what = frac * (tv.tv_sec + tv.tv_usec / 1e6);
    int32_t sec = (int32_t)what;
    return make_timeval(sec, (int32_t)((what - sec) * 1e6));
}

inline double
CalculateFlows::float_timeval(const struct timeval &tv)
{
    return tv.tv_sec + tv.tv_usec / 1e6;
}

CLICK_ENDDECLS
#endif
