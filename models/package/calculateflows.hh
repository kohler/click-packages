// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include "aggregatenotifier.hh"
#include "toipflowdumps.hh"
CLICK_DECLS

/*
=c

CalculateTCPLossEvents([I<KEYWORDS>])

=s

analyzes TCP flows for loss events

=d

Expects TCP packets with aggregate annotations set as if by AggregateIPFlows.
Packets must have timestamps in increasing order. Analyzes these TCP flows and
figures out where the loss events are. Loss events may be reported to a
ToIPFlowDumps element, and/or to a loss-event or loss-statistics file.

Keywords are:

=over 8

=item NOTIFIER

An AggregateNotifier element, such as AggregateIPFlows. CalculateTCPLossEvents
registers with the notifier to receive "delete aggregate" messages. It uses
these messages to delete state. If you don't provide a NOTIFIER,
CalculateTCPLossEvents will keep some state for every aggregate it sees until
the router quits.

=item FLOWDUMPS

A ToIPFlowDumps element. If provided, CalculateTCPLossEvents

=item LOSSFILE

Filename. If given, then output information about each loss event (or possible
or false loss event) to that file, in the following format:

  loss_type aggregate_number direction time1 seq1 time2 seq2

where C<loss_type> is the loss type, "loss" or "ploss" or "floss", and
C<direction> is either ">" or "<".

=item STATFILE

Filename. If given, then output summary information about each aggregate to
that file, in the following format:

   aggregate_number direction num_packets num_seq \
       num_loss_events num_possible_loss_events num_false_loss_events

where C<direction_number> is 0 for direction ">", and 1 for direction "<".

=item ABSOLUTE_TIME

Boolean. If true, then output absolute timestamps instead of relative ones.
Default is false.

=item ABSOLUTE_SEQ

Boolean. If true, then output absolute sequence numbers instead of relative
ones (where each flow starts at sequence number 0). Default is false.

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
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    
    void aggregate_notify(uint32_t, AggregateEvent, const Packet *packet);
    
    Packet *simple_action(Packet *);
    
    struct StreamInfo;
    class LossInfo;
    struct Pkt;
    enum LossType { NO_LOSS, LOSS, POSSIBLE_LOSS, FALSE_LOSS };

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    ToIPFlowDumps *flow_dumps() const	{ return _tipfd; }
    FILE *loss_file() const		{ return _loss_file; }
    FILE *stat_file() const		{ return _stat_file; }
    bool absolute_time() const		{ return _absolute_time; }
    bool absolute_seq() const		{ return _absolute_seq; }
    bool ack_match() const		{ return _ack_match; }

    static double float_timeval(const struct timeval &);
    
    typedef BigHashMap<unsigned, LossInfo *> MapLoss;
    
  private:
    
    MapLoss _loss_map;

    ToIPFlowDumps *_tipfd;
    FILE *_loss_file;
    FILE *_stat_file;

    bool _absolute_time : 1;
    bool _absolute_seq : 1;
    bool _ack_match : 1;
    
    Pkt *_free_pkt;
    Vector<Pkt *> _pkt_bank;

    String _loss_filename;
    String _stat_filename;

    Pkt *new_pkt();
    inline void free_pkt(Pkt *);
    inline void free_pkt_list(Pkt *, Pkt *);
    
};

struct CalculateFlows::Pkt {
    Pkt *next;
    Pkt *prev;

    tcp_seq_t seq;		// sequence number of this packet
    tcp_seq_t last_seq;		// last sequence number of this packet
    struct timeval timestamp;	// timestamp of this packet

    // exactly one of these flags is true
    enum Type { UNKNOWN, ALL_NEW, REXMIT, PARTIAL_REXMIT, ODD_REXMIT, REORDERED };
    Type type;			// type of packet

    tcp_seq_t event_id;		// ID of loss event
    Pkt *rexmit_pkt;		// retransmission of this packet

    uint32_t nacks;		// number of times this packet was acked
    
    void init(tcp_seq_t seq, uint32_t seqlen, const struct timeval &, tcp_seq_t event_id);
};

struct CalculateFlows::StreamInfo {
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
    LossType loss_type;		// type of loss event
    tcp_seq_t loss_seq;		// first seqno in loss event
    tcp_seq_t loss_last_seq;	// last seqno in loss event
    struct timeval loss_time;	// first time in loss event
    struct timeval loss_end_time; // last time in loss event
    
    StreamInfo();

    void insert(Pkt *insertion);
    Pkt *find_acked_pkt(tcp_seq_t, const struct timeval &);

    void output_loss(LossInfo *, unsigned direction, CalculateFlows *);
    
};

class CalculateFlows::LossInfo {  public:
    
    LossInfo(const Packet *);
    void kill(CalculateFlows *);

    uint32_t aggregate() const		{ return _aggregate; }
    const struct timeval &init_time() const { return _init_time; }

    void handle_packet(const Packet *, CalculateFlows *);
    
    Pkt *pre_update_state(const Packet *, CalculateFlows *);
    void calculate_loss_events2(Pkt *, unsigned dir, CalculateFlows *);
    void post_update_state(const Packet *, Pkt *, CalculateFlows *);
    
  private:

    uint32_t _aggregate;
    struct timeval _init_time;
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

inline void
CalculateFlows::Pkt::init(tcp_seq_t seq_, uint32_t seqlen_, const struct timeval &timestamp_, tcp_seq_t eid_)
{
    next = prev = 0;
    seq = seq_;
    last_seq = seq_ + seqlen_;
    timestamp = timestamp_;
    type = UNKNOWN;
    event_id = eid_;
    nacks = 0;
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
