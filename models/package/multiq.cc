// -*- c-basic-offset: 4 -*-
#include <click/config.h>
#include "avh.hh"
#include <float.h>
#include <algorithm>
CLICK_DECLS

double
Histogram::data_epsilon(const double *cur, const double *end)
{
    if (cur >= end)
	return DBL_EPSILON;

    double min_span_sep = DBL_MAX;
    int max_span_length = 0;

    /* Iterate over spans, where a span is a set of contiguous values that are
       effectively equal */
    while (cur < end) {
	/* A value small relative to *cur */
	double cur_epsilon = (DBL_EPSILON * 2) * fabs(*cur);
	
	double sep = 0;
	const double *first = cur;

	// Move one past this span
	for (cur++; cur < end && (sep = *first - *cur) < cur_epsilon; cur++)
	    /* nada */;

	// Remember the maximum span length, and the minimum separation
	// between spans
	if (first - cur > max_span_length)
	    max_span_length = first - cur;
	if (sep >= cur_epsilon && sep < min_span_sep)
	    min_span_sep = sep;
    }

    // Return a value small relative to any distance between data points
    return .01 * min_span_sep / max_span_length;
}


// !(h = avh (flags, pfx, x, n, x_eps, M,     &t,       m,    W, edge, nedge)))
//            flags, pfx, x, n, eps,   s_max, d_thresh, cmin, wmin, edge, nedge
// Note: edge, nedge specify a regular grid

// -> vh_mk(h, x, n, d_thresh)

void
Histogram::add_sorted(const double *cur, const double *end)
    // add sorted 'cur..end' values to the histogram
{
    while (cur < end && *cur < _left)
	cur++;
    if (cur >= end)
	return;

    // make sure histogram is big enough
    int max_bin = (int)((end[-1] - _left) / _width);
    if (max_bin >= _count.size())
	_count.resize(max_bin + 1, (_count.size() ? _count.back() : 0));
    _nitems += end - cur;

    // sweep through
    for (int bin = 0; bin < _count.size(); bin++) {
	double bin_right = _left + bin*_width;
	const double *first = cur;
	while (cur < end && *cur < bin_right)
	    cur++;
	_count[bin] += cur - first;
    }
}



static inline double
kde_kernel(double x)		// epanechikov
{
    return 0.75 * (1 - x*x);
}

void
Histogram::make_kde_sorted(const double *cur_lo, const double *end, const double width, double dx)
{
    assert(cur_lo < end);
    
    const double width_inverse = 1/width;

    if (dx < 0)
	dx = width / -dx;

    _left = cur_lo[0] - width - dx;
    _width = dx;
    // k->wmin = _width;
    int nbins = (int)((end[-1] - cur_lo[0])/dx) + 3;
    _count.assign(nbins, 0);
    _nitems = end - cur_lo;
    
    const double *cur_hi = cur_lo;
    
    for (int i = 1; i < nbins; i++) {
	double bin_left = _left + i*dx;
	
	while (cur_lo < end && *cur_lo < bin_left - width)
	    cur_lo++;
	while (cur_hi < end && *cur_hi < bin_left + width)
	    cur_hi++;

	double p = 0;
	for (const double *cur = cur_lo; cur < cur_hi; cur++)
	    p += kde_kernel((bin_left - *cur) * width_inverse);
	_count[i] = p;
	/* NOTE: must multiply _count[] by dx / w to get proper CDF */
    }
}



/* A mode is the highest point in any region statistically more likely than one
   before and one after it.  I cannot figure out a way to identify modes in one
   pass.  Gradual mode accumulation confuses such strategies.  So we suck it up
   and do multiple passes -- one to identify all local maxima, one to bracket
   these as significant, another to coalesce duplicates, and a final one to
   emit the proper x-value in each mode. */

struct Histogram::Mode {
    int a, i, b;
    inline Mode(int aa, int ii, int bb) : a(aa), i(ii), b(bb) { }
};

inline bool
operator<(const Histogram::Mode &a, const Histogram::Mode &b)
{
    if (a.i < 0 || b.i < 0)
	return b.i - a.i;
    else if (a.a != b.a)
	return a.a - b.a;
    else if (a.i != b.i)
	return a.i - b.i;
    else
	return a.b - b.b;
}

void
Histogram::modes(double sd, double min_points, Vector<double> &mode_x, Vector<double> &mode_prob) const
{
    assert(min_points > 0);
    Vector<double> p;
    Vector<double> sigp;

    Vector<Mode> modes;

    // collect local maxima in 'modes' array
    double last_delta = -1;
    for (int bin = 1; bin < _count.size(); bin++) {
	double delta = _count[bin] - _count[bin - 1];
	if (delta < 0 && last_delta >= 0 && delta >= min_points)
	    modes.push_back(Mode(0, bin - 1, 0));
	last_delta = delta;
    }

    // bracket each mode by expanding (a,b)
    for (Mode *m = modes.begin(); m < modes.end(); m++) {
	double p0 = prob(m->i);
	double p_thresh = p0 - sd * sig_prob(m->i);
	if (p_thresh < 0)
	    p_thresh = 0;

	int b;
	for (b = m->i - 1; b >= 0 && prob(b) > p_thresh; b--)
	    if (prob(b) > p0)	// earlier max with no dip
		goto kill_this_mode;
	m->a = b;
	for (b = m->i + 1; b < _count.size() && prob(b) > p_thresh; b++)
	    if (prob(b) > p0)	// later max with no dip
		goto kill_this_mode;
	m->b = b;
	continue;

      kill_this_mode:
	m->i = -1;
    }

    /* coalesce overlapping modes into "mode of modes" (i.e. tallest) */
    std::sort(modes.begin(), modes.end());
    Mode *next_m = modes.begin() + 1;
    for (Mode *m = modes.begin(); next_m < modes.end(); next_m++) {
	if (next_m->i < 0)
	    /* do nothing */;
	else if (m->i >= 0 && next_m->i < m->b) { // next mode inside
	    if (prob(next_m->i) > prob(m->i))
		m->i = next_m->i;
	    if (next_m->b > m->b)
		m->b = next_m->b;
	    next_m->i = -1;
	} else
	    m = next_m;
    }

    // density normalization
    for (Mode *m = modes.begin(); m < modes.end(); m++)
	if (m->i >= 0) {
	    mode_x.push_back(_left + (m->i + 0.5)*_width);
	    mode_prob.push_back(prob(m->i));
	}
}

CLICK_ENDDECLS

#include <iostream>
using namespace std;

int
main(int c, char **v)
{
    Vector<double> nums;
    double num;
    while (cin >> num)
	nums.push_back(num);
    std::sort(nums.begin(), nums.end());

    Histogram h;
    h.make_kde_sorted(nums.begin(), nums.end(), .1, -18);
    Vector<double> mx, mprob;
    h.modes(2, 10, mx, mprob);
    for (int i = 0; i < mx.size(); i++)
	cout << mx[i] << ' ' << mprob[i] << '\n';
    return 0;
}

#include <click/vector.cc>
