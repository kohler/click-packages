// -*- c-basic-offset: 4 -*-
#ifndef CLICK_MODELS_AVH_HH
#define CLICK_MODELS_AVH_HH
#include <click/vector.hh>
#include <math.h>
CLICK_DECLS

class Histogram { public:

    Histogram() { }

    inline double prob(int bin) const;
    inline double sig_prob(int bin) const;
    
    void add_sorted(const double *begin, const double *end);
    void make_kde_sorted(const double *begin, const double *end, const double width, double dx);

    void modes(double sd, double min_pts, Vector<double> &mode_x, Vector<double> &mode_prob) const;
    
    static double data_epsilon(const double *begin, const double *end);

    struct Mode;
    
  private:

    double _left;
    double _width;
    
    typedef double count_t;
    Vector<count_t> _count;
    uint32_t _nitems;
    
};


inline double
Histogram::prob(int bin) const
{
    return _count[bin] * _nitems / _width;
}

inline double
Histogram::sig_prob(int bin) const
{
    return sqrt(_count[bin]) * _nitems / _width;
}

CLICK_ENDDECLS
#endif
