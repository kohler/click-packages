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
#if CLICK_USERLEVEL
# define TCPCOLLECTOR_XML 1
#endif

/*
=c

TCPCollector([TRACEINFO, I<keywords> TRACEINFO, SOURCE, TRACEINFO_TRACEFILE, NOTIFIER, FLOWDUMPS, SUMMARYDUMP, IP_ID, ACKLATENCY])

=s

collects information about TCP flows

=d

Expects TCP packets with aggregate annotations set as if by AggregateIPFlows.
Packets must have timestamps in increasing order.  Collects information about
the TCP connections, including a small record for every packet, and can
optionally write that information to an XML file.  Other elements can call
TCPCollector methods to write other information to the XML file, or to attach
more data to each packet record or connection record.

Keywords are:

=over 8

=item TRACEINFO

Filename.  If given, then output information about each aggregate to that
file, in an XML format.  The XML format looks like this:

   <trace file='/Users/kohler/click-pkg/models/examples/sample.dump'>
   <flow aggregate='1' src='146.164.69.8' sport='33397' dst='192.150.187.11' dport='80' begin='1028667433.955909' duration='131.647561' filepos='24'>
     <stream dir='0' ndata='3' nack='1508' beginseq='1543502210' seqlen='748' sentsackok='yes'>
     </stream>
     <stream dir='1' ndata='2487' nack='0' beginseq='2831743689' seqlen='3548305'>
     </stream>
   </flow>
   ...
   </trace>

=item SOURCE

Element. If provided, the results of that element's 'C<filename>' and
'C<packet_filepos>' read handlers will be recorded in the TRACEINFO dump.  (It
is not an error if the element doesn't have those handlers.)  The
'C<packet_filepos>' results may be particularly useful, since a reader can use
those results to skip ahead through a trace file.  'C<filename>' is stored as
a C<file> attribute on the C<trace> element, and 'C<packet_filepos>' is stored
as C<filepos> attributes on any C<flow> elements.

=item NOTIFIER

An AggregateNotifier element, such as AggregateIPFlows.
CalculateTCPLossEvents registers with the notifier to receive "delete
aggregate" messages.  It uses these messages to delete state.  If you don't
provide a NOTIFIER, CalculateTCPLossEvents will keep some state for every
aggregate it sees until the router quits.

=item IP_ID

Boolean.  If true, then use IP ID to distinguish network duplicates from
retransmissions.  Default is true.

=item PACKET

Boolean.  If true, then write summaries of each data packet to the TRACEINFO
file, in "C<E<lt>packetE<gt>>" elements nested inside each
"C<E<lt>streamE<gt>>".  Each line has the format "I<timestamp> I<seq>
I<seqlen> I<ack>", where I<timestamp> is the packet's timestamp, I<seq> its
initial sequence number, I<seqlen> its sequence number length, and I<ack> its
acknowledgement number.  Default is false.

=item FULLRCVWINDOW

Boolean.  If true, then write summaries of any data packets that fill the
receiver's advertised window to the TRACEINFO file, in
"C<E<lt>fullrcvwindowE<gt>>" XML elements nested inside each
"C<E<lt>streamE<gt>>".  Each line has the format "I<timestamp> I<endseq>",
where I<timestamp> is the packet's timestamp and I<endseq> is its end sequence
number.  Default is false.

=item WINDOWPROBE

Boolean.  If true, then write summaries of any window probes to the TRACEINFO
file, in "C<E<lt>windowprobe<gt>>" XML elements nested inside each
"C<E<lt>streamE<gt>>".  Each line has the format "I<timestamp> I<endseq>",
where I<timestamp> is the packet's timestamp and I<endseq> is its end sequence
number.  Default is false.

=item INTERARRIVAL

Boolean.  If true, then write packet interarrival times to the TRACEINFO file,
in "C<E<lt>interarrivalE<gt>>" XML elements nested inside each
"C<E<lt>streamE<gt>>".  Each line is an interarrival time in microseconds.
Default is false.

=back

=e

   FromDump(-, STOP true, FORCE_IP true)
      -> IPClassifier(tcp)
      -> af :: AggregateIPFlows
      -> TCPCollector(tcpinfo.xml, NOTIFIER af)
      -> Discard;

=a

AggregateIPFlows */

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

    static inline uint32_t calculate_seqlen(const click_ip *, const click_tcp *);
    HandlerCall *filepos_h() const	{ return _filepos_h; }

#if TCPCOLLECTOR_XML
    // XML writing functions
    int add_trace_xmlattr(const String &attrname, const String &value);
    typedef String (*ConnectionXMLAttrHook)(const ConnInfo &, const String &attrname, void *thunk);
    int add_connection_xmlattr(const String &attrname, ConnectionXMLAttrHook, void *thunk);
    typedef String (*StreamXMLAttrHook)(const StreamInfo &, const ConnInfo &, const String &attrname, void *thunk);
    int add_stream_xmlattr(const String &attrname, StreamXMLAttrHook, void *thunk);
    typedef void (*StreamXMLTagHook)(FILE *f, const StreamInfo &, const ConnInfo &, const String &tagname, void *thunk);
    int add_stream_xmltag(const String &tagname, StreamXMLTagHook, void *thunk);
#endif
    
    typedef HashMap<unsigned, ConnInfo *> ConnMap;
    
  private:
    
    ConnMap _conn_map;

    bool _ip_id : 1;
    
    Pkt *_free_pkt;
    Vector<Pkt *> _pkt_bank;

    HandlerCall *_filepos_h;
    Element *_packet_source;

#if TCPCOLLECTOR_XML
    String _traceinfo_filename;
    FILE *_traceinfo_file;
#endif
    
#if TCPCOLLECTOR_XML
    // XML hooks
    Vector<String> _trace_xmlattr_name;
    Vector<String> _trace_xmlattr_value;

    struct XMLHook {
	String name;
	union {
	    ConnectionXMLAttrHook connection;
	    StreamXMLAttrHook stream;
	    StreamXMLTagHook streamtag;
	} hook;
	void *thunk;
	inline bool operator()(const XMLHook &) const;
    };
    Vector<XMLHook> _conn_xmlattr;
    Vector<XMLHook> _stream_xmlattr;
    Vector<XMLHook> _stream_xmltag;
    
    int add_xmlattr(Vector<XMLHook> &, const XMLHook &);
#endif

    Pkt *new_pkt();
    inline void free_pkt(Pkt *);
    inline void free_pkt_list(Pkt *, Pkt *);

    void kill_conn(ConnInfo *);

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
	F_FRAGMENT = 0x1000,	// packet was a fragment
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

    uint32_t mtu;		// IP MTU (length of largest IP packet seen)

    Pkt *pkt_head;		// first packet record
    Pkt *pkt_tail;		// last packet record
    Pkt *pkt_data_tail;		// last packet record with data

    StreamInfo();

    void process_data(Pkt *, const Packet *, ConnInfo *conn);
    void process_options(const click_tcp *, int transport_length);
    void process_ack(Pkt *, const Packet *, StreamInfo &stream);
    void attach_packet(Pkt *);

#if TCPCOLLECTOR_XML
    void write_xml(FILE *, const ConnInfo &, const TCPCollector *) const;
    static void packet_xmltag(FILE *, const StreamInfo &, const ConnInfo &, const String &, void *);
    static void fullrcvwindow_xmltag(FILE *, const StreamInfo &, const ConnInfo &, const String &, void *);
    static void windowprobe_xmltag(FILE *, const StreamInfo &, const ConnInfo &, const String &, void *);
    static void interarrival_xmltag(FILE *, const StreamInfo &, const ConnInfo &, const String &, void *);
#endif

};

class TCPCollector::ConnInfo {  public:
    
    ConnInfo(const Packet *, const HandlerCall *, bool ip_id);

    uint32_t aggregate() const		{ return _aggregate; }
    bool ip_id() const			{ return _ip_id; }
    const timeval &init_time() const	{ return _init_time; }
    timeval duration() const;
    const StreamInfo &stream(int i) const { assert(i==0||i==1); return _stream[i]; }

    void handle_packet(const Packet *, TCPCollector *);
    
#if TCPCOLLECTOR_XML
    void write_xml(FILE *, const TCPCollector *) const;
#endif
    
  private:

    uint32_t _aggregate;	// aggregate number
    IPFlowID _flowid;		// flow identifier for _stream[0]
    struct timeval _init_time;	// first time seen in stream
    String _filepos;		// file position of first packet
    bool _ip_id : 1;		// use IP ID to distinguish duplicates?
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
