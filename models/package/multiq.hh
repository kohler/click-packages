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

=s

calculates capacity information using EMG

=d

Calculates capacity information using equally-spaced mode gaps.  MultiQ works
in two ways.  First, it calculates interarrival times of any packets fed to
its input; capacity information about these packets is available via the
"capacities" handler.  Second, if you supply the name of a TCPCollector
element via the TCPCOLLECTOR keyword, MultiQ will write capacity information
for each significant TCP flow into the TCPCollector's output XML file.

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

   FromDump(-, STOP true, FORCE_IP true)
      -> IPClassifier(tcp)
      -> af :: AggregateIPFlows
      -> TCPCollector(tcpinfo.xml, NOTIFIER af)
      -> Discard;

=a

TCPCollector */

class MultiQ : public Element { public:

    MultiQ();
    ~MultiQ();

    const char *class_name() const	{ return "MultiQ"; }

    void notify_ninputs(int);
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
    
    bool significant_flow(const TCPCollector::StreamInfo &stream, const TCPCollector::ConnInfo &conn) const;

    static String read_capacities(Element *, void *);
    static void multiqcapacity_xmltag(FILE *f, const TCPCollector::StreamInfo &stream, const TCPCollector::ConnInfo &conn, const String &tagname, void *thunk);
    
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
