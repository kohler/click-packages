// -*- c-basic-offset: 4 -*-
#ifndef CLICK_MODELS_MULTIQ_HH
#define CLICK_MODELS_MULTIQ_HH
#include <click/vector.hh>
#include <click/pair.hh>
#include <math.h>
#include "tcpcollector.hh"
CLICK_DECLS
class Histogram;

/*
=c

MultiQ([I<keywords> TCPCOLLECTOR, RAW_TIMESTAMP, MIN_SCALE])

=s ipmeasure

calculates capacity information using EMG

=d

Calculates capacity information using equally-spaced mode gaps.  MultiQ works
in two ways.  First, it calculates interarrival times of any packets fed to
its input; capacity information about these packets is available via the
"capacities" handler.  Second, if you supply the name of a TCPCollector
element via the TCPCOLLECTOR keyword, MultiQ will write capacity information
for each significant TCP flow into the TCPCollector's output XML file.  (A
flow is significant if it had a 1500-byte MTU, it contained at least 50 data
packets, and its rate was greater than 9.5 packets per second.)

MultiQ has either zero or one inputs, and the same number of outputs.

Keywords are:

=over 8

=item TCPCOLLECTOR

The name of a TCPCollector element.

=item RAW_TIMESTAMP

Boolean.  If true, then input packet timestamps are used raw (MultiQ will not
calculate interarrivals).  Default is false.

=item MIN_SCALE

Real number.  The initial scale to use in the MultiQ algorithm.  Default is 10
microseconds.

=back

=h capacities read-only

Returns capacities inferred from the current set of packet interarrivals.
Only available if MultiQ has an input.

=h ack_capacities read-only

Returns capacities inferred from the current set of packet interarrivals,
assuming that these packet interarrivals are acks.  Only available if MultiQ
has an input.

=e

This configuration reads a tcpdump(1) file on the standard input, calculates
capacities for every TCP flow it contains, and writes an XML file to
F<tcpinfo.xml> containing MultiQ capacity information for every significant
flow in the trace.

   require(models);
   d :: FromDump(-, STOP true, FORCE_IP true)
      -> IPClassifier(tcp)
      -> a :: AggregateIPFlows
      -> tcpc :: TCPCollector(tcpinfo.xml, SOURCE d, NOTIFIER a)
      -> Discard;
   MultiQ(TCPCOLLECTOR tcpc);

After running Click on this configuration, F<tcpinfo.xml> might look like
this:

   <?xml version='1.0' standalone='yes'?>
   <trace file='<stdin>'>

   <flow aggregate='1' src='146.164.69.8' sport='33397' dst='192.150.187.11' dport='80' begin='1028667433.955909' duration='131.647561' filepos='24'>
     <stream dir='0' ndata='3' nack='1508' beginseq='1543502210' seqlen='748' mtu='430' sentsackok='yes'>
       <multiq_capacity type='ack' scale='25.3' time='1313.299' bandwidth='9.454' commonbandwidth='10.000' commontype='10bT' bandwidth52='0.317' commonbandwidth52='0.317' commontype52='?' />
       <multiq_capacity type='ack' scale='10.0' time='23.031' bandwidth='539.103' commonbandwidth='622.080' commontype='OC12' bandwidth52='18.063' commonbandwidth52='18.063' commontype52='?' />
     </stream>
     <stream dir='1' ndata='2487' nack='0' beginseq='2831743689' seqlen='3548305' mtu='1500'>
       <multiq_capacity type='data' scale='760.2' time='1286.668' bandwidth='9.326' commonbandwidth='10.000' commontype='10bT' bandwidth52='0.323' commonbandwidth52='0.323' commontype52='?' />
       <multiq_capacity type='data' scale='74.0' time='691.101' bandwidth='17.364' commonbandwidth='17.364' commontype='?' bandwidth52='0.602' commonbandwidth52='0.602' commontype52='?' />
     </stream>
   </flow>

   <flow aggregate='2' src='203.167.213.81' sport='23568' dst='192.150.187.11' dport='80' begin='1028686953.640701' duration='45.544054' filepos='346485'>
     <stream dir='0' ndata='3' nack='63' beginseq='3453338283' seqlen='486' mtu='524' sentsackok='yes'>
     </stream>
     <stream dir='1' ndata='110' nack='1' beginseq='3034663568' seqlen='159102' mtu='1500'>
     </stream>
   </flow>

   </trace>

The second flow has no C<E<lt>multiq_capacityE<gt>> annotations because it was
not significant.

The following configuration assumes that the input tcpdump(1) file contains
information about one direction of a significant flow.  The MultiQ element
reads interarrival times from passing packets.

   require(models);
   FromDump(-, FORCE_IP true, STOP true)
     -> m::MultiQ
     -> Discard;
   DriverManager(wait_stop, save m.capacities -);

This configuration wil print capacity information to standard output, in the
following format:

       w     NTT (us)  1500-BW    40-BW (1500-BW) (40-BW)
    163.2   955.744    12.556    0.435   12.556    0.435
     13.3   148.382    80.872    2.804  100.000    2.804

If your dump file has more than one flow in it, use IPFilter,
AggregateIPFlows, AggregateFilter, and/or CheckPaint to select one flow from
the background.

Finally, you can use MultiQ and FromIPSummaryDump to figure out capacity
information from flat files of interarrival times.  Create a file of
interarrival times, where there's one interarrival time, measured in
microseconds, per line.  For example:

   209878
   38718
   492618
   73

Then feed that file into this configuration.

   require(models);
   FromIPSummaryDump(-, CONTENTS usec1, STOP true)
     -> m::MultiQ(RAW_TIMESTAMP true)
     -> Discard;
   DriverManager(wait_stop, save m.capacities -);

The output format is the same as above.

=a

TCPCollector, FromIPSummaryDump, FromDump, DriverManager */

class MultiQ : public Element { public:

    MultiQ();
    ~MultiQ();

    const char *class_name() const	{ return "MultiQ"; }
    const char *port_count() const	{ return "0-1/="; }

    int configure(Vector<String> &, ErrorHandler *);
    void add_handlers();

    Packet *simple_action(Packet *);

    // calculate capacities
    enum MultiQType { MQ_DATA, MQ_ACK };
    struct Capacity {
	double scale;
	double ntt;

	double bandwidth;
	double common_bandwidth;
	const char *common_bandwidth_name;

	double bandwidth52;
	double common_bandwidth52;
	const char *common_bandwidth52_name;

	Capacity(MultiQType, double scale_, double ntt_);
    };
    void run(MultiQType, Vector<double> &interarrivals /* sorted on return */,
	     Vector<Capacity> &out) const;

    // common bandwidths
    struct BandwidthSpec {
	const char *name;
	double bandwidth, range_lo, range_hi;
    };
    static const BandwidthSpec *closest_common_bandwidth(double);

    // tunable constants; see MultiQ::MultiQ for default values
    double INTERARRIVAL_CUTOFF;
    double MIN_SCALE;
    double MAX_SCALE;
    double SCALE_STEP;
    double SCALE_STEP_NOMODES;
    double SIGNIFICANCE;
    double MIN_POINTS;
    double GAP_SIGNIFICANCE;
    double GAP_MIN_POINTS;
    double MODES_SIMILAR;

    class Histogram;

  private:

    Vector<double> _thru_interarrivals;
    double _thru_last;

    enum { NBANDWIDTH_SPEC = 10 };
    static const BandwidthSpec bandwidth_spec[NBANDWIDTH_SPEC];

    double modes2ntt(MultiQType, const Histogram &, const Vector<int> &modes) const;
    double adjust_max_scale(MultiQType, const double *begin, const double *end, double tallest_mode_min_scale) const;
    void create_capacities(MultiQType, const double *begin, const double *end, Vector<Capacity> &) const;
    void filter_capacities(Vector<Capacity> &) const;

    bool significant_flow(const TCPCollector::Stream* stream, const TCPCollector::Conn* conn) const;

    static String read_capacities(Element *, void *);
    static void multiqcapacity_xmltag(FILE* f, TCPCollector::Stream* stream, TCPCollector::Conn* conn, const String& tagname, void* thunk);

};

class MultiQ::Histogram { public:

    Histogram()				{ }
    typedef double count_t;

    void make_kde_sorted(const double *begin, const double *end, const double width /* lade -w */, double dx = -18.0);

    void modes(double significance /* lade -em */, double min_points /* lade -Y */, Vector<int> &modes) const;

    int size() const			{ return _count.size(); }
    int nitems() const			{ return _nitems; }

    double pos(int i) const		{ return _left + i*_bin_width; }
    double pos(double i) const		{ return _left + i*_bin_width; }
    // For results identical to the current multiQ, set mode_pos(i) == pos(i)
    double mode_pos(int i) const	{ return pos(i); }
    count_t count(int bin) const	{ return _count[bin]; }
    inline double prob(int bin) const;
    inline double kde_prob(int bin) const;
    inline double kde_sig_prob(int bin) const;

  private:

    double _left;
    double _bin_width;
    double _kde_width;

    Vector<count_t> _count;
    int _nitems;

};

inline double
MultiQ::Histogram::prob(int bin) const
{
    return _count[bin] / _nitems;
}

inline double
MultiQ::Histogram::kde_prob(int bin) const
{
    return _count[bin] / (_nitems * _kde_width);
}

inline double
MultiQ::Histogram::kde_sig_prob(int bin) const
{
    return sqrt(_count[bin]) / (_nitems * _kde_width);
}

CLICK_ENDDECLS
#endif
