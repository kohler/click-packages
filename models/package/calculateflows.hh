// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <math.h>
#include "aggregatenotifier.hh"
#include "toipflowdumps.hh"
#undef CF_PKT

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
    
    struct TimeInterval {
	struct timeval time;
	uint32_t start_seq;
	uint32_t end_seq;
	TimeInterval(): start_seq(0), end_seq(0) { }
    };

    class StreamInfo;
    class LossInfo;

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    
    typedef BigHashMap<unsigned, short int> MapS;
    typedef BigHashMap<unsigned, timeval> MapT;
    typedef BigHashMap<unsigned, TimeInterval> MapInterval;
    typedef BigHashMap<unsigned, LossInfo*> MapLoss;
    
  private:
    
    String _outfilename[2];
    ToIPFlowDumps *_tipfd;
    
    MapLoss _loss_map;

#if CF_PKT
    Pkt *_free_pkt;
    Vector<Pkt *> _pkt_bank;

    Pkt *new_pkt();
    inline void free_pkt(Pkt *);
#endif
    
};

struct CalculateFlows::StreamInfo {
    bool have_init_seq : 1;	// have we seen a sequence number yet?
    bool have_syn : 1;		// have we seen a SYN?
    bool have_fin : 1;		// have we seen a FIN?
    
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

    uint32_t lost_packets;	// number of packets lost (incl. multiple loss)
    uint32_t lost_seq;		// sequence space lost
    
    StreamInfo();
};

class CalculateFlows::LossInfo {  public:
    
    LossInfo(const Packet *, bool eventfiles, const String *outfilenames);

    ~LossInfo() {
	if (_eventfiles)
	    print_stats();
	
	/*	if (gnuplot){  // check if gnuplot output is requested.
		char tempstr[32];
		for (int i = 0 ; i < 2 ; i++){
		sprintf(tempstr,"./crplots.sh %s",outfilename[i].cc());
		//			printf("./crplots.sh %s",outfilename[i].cc());
		system(tempstr);
		}
		}*/
    }

    String output_directory() const	{ return _outputdir; }
    
    void print_stats();

    void handle_packet(const Packet *, ToIPFlowDumps *);
    
    void pre_update_state(const Packet *);
    void post_update_state(const Packet *);
    
    struct timeval Search_seq_interval(tcp_seq_t start_seq, tcp_seq_t end_seq, unsigned paint);
    
    static double timesub(const timeval &end_time, const timeval &start_time) {
	return (end_time.tv_sec - start_time.tv_sec) + 0.000001 * (end_time.tv_usec - start_time.tv_usec);
    }
    static double timeadd(const timeval &end_time, const timeval &start_time) {
	return (end_time.tv_sec + start_time.tv_sec) + 0.000001 * (end_time.tv_usec + start_time.tv_usec);
    }
    
    void calculate_loss_events2(tcp_seq_t seq, uint32_t seqlen, const timeval &time, unsigned paint, ToIPFlowDumps *tipfdp);

    void calculate_loss(tcp_seq_t seq, uint32_t seqlen, unsigned paint);
    
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
    
    bool _out_of_order;

    MapT time_by_firstseq[2];
    MapT time_by_lastseq[2];
    MapInterval inter_by_time[2];
    MapS _acks[2];
    MapS rexmt[2];
    
    bool _eventfiles;
    String _outputdir;
    String _outfilename[2];	// Event output files using Jitu format 
    
};

inline uint32_t
CalculateFlows::calculate_seqlen(const click_ip *iph, const click_tcp *tcph)
{
    return (ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2)) + (tcph->th_flags & TH_SYN ? 1 : 0) + (tcph->th_flags & TH_FIN ? 1 : 0);
}

#if CF_PKT
inline void
CalculateFlows::free_pkt(Pkt *p)
{
    if (p) {
	p->next = _free_pkt;
	_free_pkt = p;
    }
}
#endif

#endif
