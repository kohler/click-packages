// -*- c-basic-offset: 4 -*-
#ifndef CLICK_MODELS_AVH_HH
#define CLICK_MODELS_AVH_HH
#include <click/vector.hh>
#include <math.h>
CLICK_DECLS

class Histogram { public:

    Histogram() { }
    typedef double count_t;

    inline double prob(int bin) const;
    inline double sig_prob(int bin) const;
    
    void add_sorted(const double *begin, const double *end);
    void make_kde_sorted(const double *begin, const double *end, const double width, double dx);

    void modes(double sd, double min_pts, Vector<double> &mode_x, Vector<double> &mode_prob) const;

    int size() const			{ return _count.size(); }
    int nitems() const			{ return _nitems; }
    double left() const			{ return _left; }
    double bin_left(int i) const	{ return _left + i*_width; }
    double bin_left(double i) const	{ return _left + i*_width; }
    double bin_center(int i) const	{ return _left + (i + 0.5)*_width; }
    double bin_width() const		{ return _width; }
    double width() const		{ return _kde_width; }
    
    count_t count(int i) const		{ return _count[i]; }
    const count_t *count_begin() const	{ return _count.begin(); }
    const count_t *count_end() const	{ return _count.end(); }
    
    static double data_epsilon(const double *begin, const double *end);

    struct Mode;
    
  private:

    double _left;
    double _width;
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
