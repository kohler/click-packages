// -*- c-basic-offset: 4 -*-
#ifndef CLICK_TCPCOLLECTOR_HH
#define CLICK_TCPCOLLECTOR_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <click/ipflowid.hh>
#include <clicknet/tcp.h>
#include "elements/analysis/aggregatenotifier.hh"
CLICK_DECLS
class HandlerCall;

/*
=c

CalculateTCPLossEvents([TRACEINFO, I<keywords> TRACEINFO, TRACEINFO_FILEPOS, TRACEINFO_TRACEFILE, NOTIFIER, FLOWDUMPS, SUMMARYDUMP, IP_ID, ACKLATENCY])

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

class TCPCollector : public Element, public AggregateListener { public:

    TCPCollector();
    ~TCPCollector();

    const char *class_name() const	{ return "TCPCollector"; }
    const char *processing() const	{ return "a/ah"; }

    void notify_noutputs(int);
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();
    
    void aggregate_notify(uint32_t, AggregateEvent, const Packet *packet);
    
    Packet *simple_action(Packet *);
    
    struct StreamInfo;
    class ConnInfo;
    struct Pkt;
    enum LossType { NO_LOSS, LOSS, POSSIBLE_LOSS, FALSE_LOSS };

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    FILE *traceinfo_file() const	{ return _traceinfo_file; }
    HandlerCall *filepos_h() const	{ return _filepos_h; }

    enum WriteFlags { WR_FULLRCVWND = 4, WR_WINDOWPROBE = 16, WR_PACKETS = 32 };
    WriteFlags write_flags() const	{ return (WriteFlags)_write_flags; }

    typedef HashMap<unsigned, ConnInfo *> ConnMap;
    
  private:
    
    ConnMap _conn_map;

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

struct TCPCollector::Pkt {
    Pkt *next;
    Pkt *prev;

    uint32_t data_packetno;	// data packet number of this packet
    tcp_seq_t seq;		// sequence number of this packet
    tcp_seq_t end_seq;		// end sequence number of this packet
    tcp_seq_t ack;		// ack sequence number of this packet
    struct timeval timestamp;	// timestamp of this packet
    uint32_t packetno_anno;	// packet number annotation of this packet
    uint16_t ip_id;		// IP ID of this packet
    uint16_t th_flags;		// TCP flags

    enum Flags {
	F_NEW = 0x1,		// packet contains some new data
	F_NONORDERED = 0x2,	// packet is part of a non-ordered block
	F_DUPDATA = 0x4,	// packet contains some data seen before
	F_DUPLICATE = 0x10,	// packet is a network duplicate
	F_KEEPALIVE = 0x80,	// packet is a keepalive
	F_ACK_REORDER = 0x100,	// packet's ackno is reordered
	F_ACK_NONORDERED = 0x200, // packet is part of a non-ordered ack block

	F_FILLS_RCV_WINDOW = 0x400, // packet filled receive window
	F_WINDOW_PROBE = 0x800,	// packet was a window probe
    };
    int flags;			// packet flags
};

struct TCPCollector::StreamInfo {
    unsigned direction : 1;	// our direction
    bool have_init_seq : 1;	// have we seen a sequence number yet?
    bool have_syn : 1;		// have we seen a SYN?
    bool different_syn : 1;	// did we see a different SYN?
    bool have_fin : 1;		// have we seen a FIN?
    bool different_fin : 1;	// did we see a different FIN?
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

    uint32_t total_packets;	// total number of packets seen (incl. rexmits)
    uint32_t ack_packets;	// total number of pure acks seen
    uint32_t total_seq;		// total sequence space seen (incl. rexmits)
    
    tcp_seq_t end_rcv_window;	// end of receive window
    int rcv_window_scale;	// window scaling option

    Pkt *pkt_head;		// first packet record
    Pkt *pkt_tail;		// last packet record
    Pkt *pkt_data_tail;		// last packet record with data

    StreamInfo();
    ~StreamInfo();

    void process_data(Pkt *, const Packet *, ConnInfo *conn);
    void process_options(const click_tcp *, int transport_length);
    void process_ack(Pkt *, const Packet *, StreamInfo &stream);
    void attach_packet(Pkt *);

    
    void categorize(Pkt *insertion, ConnInfo *, TCPCollector *);
    void register_loss_event(Pkt *startk, Pkt *endk, ConnInfo *, TCPCollector *);
    void update_counters(const Pkt *np, const click_tcp *);

    bool mark_delivered(const Pkt *ackk, Pkt *&k_cumack, Pkt *&k_time, tcp_seq_t prev_ackno, int prev_ndupack) const;

    void finish(ConnInfo*, TCPCollector*);
    void unfinish();

    void write_xml(ConnInfo *, FILE *, WriteFlags) const;
    void write_full_rcv_window_xml(FILE *) const;
    void write_window_probe_xml(FILE *) const;
    void write_packets_xml(FILE *) const;

};

class TCPCollector::ConnInfo {  public:
    
    ConnInfo(const Packet *, const HandlerCall *);
    void kill(TCPCollector *);

    uint32_t aggregate() const		{ return _aggregate; }
    const struct timeval &init_time() const { return _init_time; }
    struct timeval rtt() const;
    const StreamInfo *stream(int i) const { assert(i==0||i==1); return &_stream[i]; }

    void handle_packet(const Packet *, TCPCollector *);
    
    Pkt *create_pkt(const Packet *, TCPCollector *);
    void calculate_loss_events(Pkt *, unsigned dir, TCPCollector *);
    void post_update_state(const Packet *, Pkt *, TCPCollector *);

    void finish(TCPCollector *);
    
  private:

    uint32_t _aggregate;	// aggregate number
    IPFlowID _flowid;		// flow identifier for _stream[0]
    struct timeval _init_time;	// first time seen in stream
    String _filepos;		// file position of first packet
    bool _finished : 1;		// have we finished the flow?
    bool _clean : 1;		// have packets been added since we finished?
    StreamInfo _stream[2];
    
};

inline uint32_t
TCPCollector::calculate_seqlen(const click_ip *iph, const click_tcp *tcph)
{
    return (ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2)) + (tcph->th_flags & TH_SYN ? 1 : 0) + (tcph->th_flags & TH_FIN ? 1 : 0);
}

inline void
TCPCollector::free_pkt(Pkt *p)
{
    if (p) {
	p->next = _free_pkt;
	_free_pkt = p;
    }
}

inline void
TCPCollector::free_pkt_list(Pkt *head, Pkt *tail)
{
    if (head) {
	tail->next = _free_pkt;
	_free_pkt = head;
    }
}

CLICK_ENDDECLS
#endif
