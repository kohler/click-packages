// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <math.h>
#include "aggregatenotifier.hh"
#include "toipflowdumps.hh"

/*
=c

CalculateFlows([FILENAME1, FILENAME2, I<KEYWORDS>])

=s

calculates loss events in flows

=d

Keywords are:

=over 8

=item NOTIFIER

An AggregateNotifier element.

=item FLOWDUMPS

A ToIPFlowDumps element. Not optional.

=back

=a

AggregateIPFlows, ToIPFlowDumps */

class CalculateFlows : public Element, public AggregateListener { public:

    CalculateFlows();
    ~CalculateFlows();

    const char *class_name() const	{ return "CalculateFlows"; }
    const char *processing() const	{ return "a/ah"; }
    CalculateFlows *clone() const	{ return new CalculateFlows; }

    void notify_noutputs(int);
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    
    void aggregate_notify(uint32_t, AggregateEvent, const Packet *packet);
    
    Packet *simple_action(Packet *);
    
    struct StreamInfo;
    class LossInfo;
    struct Pkt;
    enum LossType { NO_LOSS, LOSS, POSSIBLE_LOSS, FALSE_LOSS };

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    ToIPFlowDumps *tipfd() const	{ return _tipfd; }
    
    typedef BigHashMap<unsigned, LossInfo*> MapLoss;
    
  private:
    
    String _outfilename[2];
    ToIPFlowDumps *_tipfd;
    
    MapLoss _loss_map;

    Pkt *_free_pkt;
    Vector<Pkt *> _pkt_bank;

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

    uint32_t lost_packets;	// number of packets lost (incl. multiple loss)
    uint32_t lost_seq;		// sequence space lost

    struct timeval min_ack_bounce; // minimum time between packet and ACK

    Pkt *pkt_head;		// first packet record
    Pkt *pkt_tail;		// last packet record

    // information about the most recent loss event
    LossType loss_type;
    tcp_seq_t loss_seq;
    tcp_seq_t loss_last_seq;
    struct timeval loss_time; 
    struct timeval loss_end_time;   
    
    StreamInfo();

    void insert(Pkt *insertion);
    Pkt *find_acked_pkt(tcp_seq_t, const struct timeval &);

    void output_loss(uint32_t aggregate, unsigned direction, ToIPFlowDumps *);
};

class CalculateFlows::LossInfo {  public:
    
    LossInfo(const Packet *, bool eventfiles, const String *outfilenames);
    void kill(CalculateFlows *);

    String output_directory() const	{ return _outputdir; }
    
    void print_stats();

    void handle_packet(const Packet *, CalculateFlows *, ToIPFlowDumps *);
    
    Pkt *pre_update_state(const Packet *, CalculateFlows *);
    void post_update_state(const Packet *, Pkt *, CalculateFlows *);
    
    static double timesub(const timeval &end_time, const timeval &start_time) {
	return (end_time.tv_sec - start_time.tv_sec) + 0.000001 * (end_time.tv_usec - start_time.tv_usec);
    }
    static double timeadd(const timeval &end_time, const timeval &start_time) {
	return (end_time.tv_sec + start_time.tv_sec) + 0.000001 * (end_time.tv_usec + start_time.tv_usec);
    }
    
    void calculate_loss_events2(Pkt *, unsigned dir, ToIPFlowDumps *tipfdp);

    unsigned total_seq(unsigned paint) const {
	assert(paint < 2);
	return _stream[paint].total_seq;
    }
    uint32_t total_packets(unsigned paint) const {
	assert(paint < 2);
	return _stream[paint].total_packets;
    }
    unsigned loss_events(unsigned paint) const {
	assert(paint < 2);
	return _stream[paint].loss_events;
    }
    unsigned ploss_events(unsigned paint) const {
	assert(paint < 2);
	return _stream[paint].possible_loss_events;
    }
    unsigned lost_packets(unsigned paint) const {
	assert(paint < 2);
	return _stream[paint].lost_packets;
    }
    unsigned lost_seq(unsigned paint) const {
	assert(paint < 2);
	return _stream[paint].lost_seq;
    }

    //void calculate_loss_events(tcp_seq_t seq, uint32_t seqlen, const timeval &time, unsigned paint);
    
  private:

    uint32_t _aggregate;
    struct timeval _init_time;
    StreamInfo _stream[2];
    
    bool _eventfiles;
    String _outputdir;
    String _outfilename[2];	// Event output files using Jitu format 
    
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

#endif
