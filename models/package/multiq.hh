// -*- c-basic-offset: 4 -*-
#ifndef CLICK_MODELS_MULTIQ_HH
#define CLICK_MODELS_MULTIQ_HH
#include <click/vector.hh>
#include <click/pair.hh>
#include <math.h>
#include "tcpcollector.hh"
CLICK_DECLS
class Histogram;

class MultiQ : public Element { public:

    MultiQ();
    ~MultiQ();

    const char *class_name() const	{ return "MultiQ"; }

    int configure(Vector<String> &, ErrorHandler *);
    
    // tunable constants
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

  private:

    struct NTTSpec {
	double scale;
	double ntt;
	double raw_bandwidth;
	double bandwidth;
	NTTSpec(double scale, double ntt);
    };
    
    struct BandwidthSpec {
	const char *name;
	double bandwidth, range_lo, range_hi;
    };
    enum { NBANDWIDTH_SPEC = 10 };
    static BandwidthSpec bandwidth_spec[NBANDWIDTH_SPEC];

    static double closest_common_bandwidth(double);
    static const char *closest_common_type(double); 
    double modes2ntt(const Histogram &, const Vector<int> &modes) const;
    void create_ntts(const double *begin, const double *end, Vector<NTTSpec> &) const;
    void filter_ntts(Vector<NTTSpec> &) const;
    bool significant_flow(const TCPCollector::StreamInfo &stream, const TCPCollector::ConnInfo &conn) const;

    static void multiqcapacity_xmltag(FILE *f, const TCPCollector::StreamInfo &stream, const TCPCollector::ConnInfo &conn, const String &tagname, void *thunk);
    
};

class Histogram { public:

    Histogram()				{ }
    typedef double count_t;

    void make_kde_sorted(const double *begin, const double *end, const double width, double dx = -18.0);

    void modes(double significance, double min_points, Vector<int> &modes) const;

    int size() const			{ return _count.size(); }
    int nitems() const			{ return _nitems; }
    
    double pos(int i) const		{ return _left + i*_bin_width; }
    double pos(double i) const		{ return _left + i*_bin_width; }
    count_t count(int bin) const	{ return _count[bin]; }
    inline double prob(int bin) const;
    inline double sig_prob(int bin) const;
    
  private:

    double _left;
    double _bin_width;
    double _kde_width;
    
    Vector<count_t> _count;
    int _nitems;
    
};

inline double
Histogram::prob(int bin) const
{
    return _count[bin] / (_nitems * _kde_width);
}

inline double
Histogram::sig_prob(int bin) const
{
    return sqrt(_count[bin]) / (_nitems * _kde_width);
}

CLICK_ENDDECLS
#endif
