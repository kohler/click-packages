// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATECAPACITY_HH
#define CLICK_CALCULATECAPACITY_HH
#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/handlercall.hh>
#include "elements/analysis/aggregatenotifier.hh"
#include "elements/analysis/toipflowdumps.hh"
CLICK_DECLS
class ToIPSummaryDump;

/*
=c

CalculateTCPLossEvents([TRACEINFO, I<keywords> TRACEINFO, TRACEINFO_FILEPOS, TRACEINFO_TRACEFILE, NOTIFIER, FLOWDUMPS, SUMMARYDUMP, IP_ID, ACK_MATCH])

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

=item IP_ID

Boolean. If true, then use IP ID to distinguish network duplicates from
retransmissions. Default is true.

=back

=e

   FromDump(-, STOP true, FORCE_IP true)
      -> IPClassifier(tcp)
      -> af :: AggregateIPFlows
      -> CalculateTCPLossEvents(NOTIFIER af, FLOWDUMPS flowd)
      -> flowd :: ToIPFlowDumps(/tmp/flow%04n, NOTIFIER af);

=a

AggregateIPFlows, ToIPFlowDumps */

class CalculateCapacity : public Element, public AggregateListener { public:

    CalculateCapacity();
    ~CalculateCapacity();

    const char *class_name() const	{ return "CalculateCapacity"; }
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
    struct Pkt;

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    FILE *traceinfo_file() const	{ return _traceinfo_file; }
    HandlerCall *filepos_h() const	{ return _filepos_h; }

    typedef HashTable<unsigned, ConnInfo *> ConnMap;

  private:

    ConnMap _conn_map;

    FILE *_traceinfo_file;
    HandlerCall *_filepos_h;

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

struct CalculateCapacity::Pkt {
    Pkt *next;
    Pkt *prev;

    tcp_seq_t seq;		// sequence number of this packet
    tcp_seq_t last_seq;		// last sequence number of this packet
    tcp_seq_t ack;		// ack sequence number of this packet
    Timestamp timestamp;	// timestamp of this packet
    uint32_t hsize;             // ip+tcp header size

    int flags;			// packet flags
};

struct CalculateCapacity::StreamInfo {
    unsigned direction : 1;	// our direction
    bool have_init_seq : 1;	// have we seen a sequence number yet?

    tcp_seq_t init_seq;		// first absolute sequence number seen, if any
				// all other sequence numbers are relative

    Pkt *pkt_head;		// first packet record
    Pkt *pkt_tail;		// last packet record
    uint32_t pkt_cnt;           // how many in this stream

    uint32_t mss;               //largest single packet here
    uint32_t rmss;              // mss in reverse direction

    double datarate;
    double ackrate;
    Timestamp ackstart;
    Timestamp datastart;
    uint32_t dbytes;
    uint32_t abytes;

    struct IntervalStream;
    struct IntervalStream *intervals;
    struct Peak;

    StreamInfo();
    ~StreamInfo();

    uint32_t histpoints;
    uint32_t *hist;
    double *cutoff;
    uint8_t *valid;
    Vector<struct Peak *> peaks;

    //void categorize(Pkt *insertion, ConnInfo *, CalculateCapacity *);
    //void register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *, CalculateCapacity *);
    //void update_counters(const Pkt *np, const click_tcp *, const ConnInfo *);
    void findpeaks();
    void fill_intervals();
    void fill_shortrate();
    void histogram();
    void write_xml(FILE *) const;

};

struct CalculateCapacity::StreamInfo::IntervalStream {
    tcp_seq_t size; //packet size (incl headers)
    tcp_seq_t newack; //new ack data
    Timestamp interval; //time since previous packet
    Timestamp time; //flow-relative
};

struct CalculateCapacity::StreamInfo::Peak {
    double center;  //interval in middle
    double left;  //interval at left edge
    double right; //at right edge
    uint32_t area;
    double acknone; // < 0.5 mss
    double ackone; //frac of a peak that acks between 0.5 and 1.5 * rmss
    double acktwo; // 2* rmss
    double ackmore; // > 2 * rmss
};



class CalculateCapacity::ConnInfo {  public:

    ConnInfo(const Packet *, const HandlerCall *);
    void kill(CalculateCapacity *);

    uint32_t aggregate() const		{ return _aggregate; }
    const Timestamp &init_time() const	{ return _init_time; }

    void handle_packet(const Packet *, CalculateCapacity *);

    Pkt *create_pkt(const Packet *, CalculateCapacity *);

  private:

    uint32_t _aggregate;	// aggregate number
    IPFlowID _flowid;		// flow identifier for _stream[0]
    Timestamp _init_time;	// first time seen in stream
    String _filepos;		// file position of first packet
    StreamInfo _stream[2];

};

inline uint32_t
CalculateCapacity::calculate_seqlen(const click_ip *iph, const click_tcp *tcph)
{
    return (ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2)) + (tcph->th_flags & TH_SYN ? 1 : 0) + (tcph->th_flags & TH_FIN ? 1 : 0);
}

inline void
CalculateCapacity::free_pkt(Pkt *p)
{
    if (p) {
	p->next = _free_pkt;
	_free_pkt = p;
    }
}

inline void
CalculateCapacity::free_pkt_list(Pkt *head, Pkt *tail)
{
    if (head) {
	tail->next = _free_pkt;
	_free_pkt = head;
    }
}

CLICK_ENDDECLS
#endif
