// -*- c-basic-offset: 4 -*-
/*
 * multiq.{cc,hh} -- MultiQ capacity estimation
 * Chuck Blake (Histogram), Dina Katabi, Sachin Katti (MultiQ),
 * Eddie Kohler (C++ version)
 *
 * Copyright (c) 2003-4 Massachusetts Institute of Technology
 * Copyright (c) 2004 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "multiq.hh"
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <float.h>
#include <algorithm>
CLICK_DECLS

/****************
 * MULTIQ       *
 *              *
 ****************/

// Utilities         //
//                   //

const MultiQ::BandwidthSpec MultiQ::bandwidth_spec[MultiQ::NBANDWIDTH_SPEC] = {
    { "modem",   0.056    , 0.000     , 0.064     },
    { "cable",   0.512    , .75*0.512 , 1.25*0.512 },
    { "T1",      1.544    , .75*1.544 , 1.25*1.544 },
    { "10bT",    10       , 7         , 11.7      },
    { "T3",      29*1.544 , 26*1.544  , 32*1.544  },
    { "100bT",   100      , 71        , 120       },
    { "OC3",     155.52   , 130       , 165       },
    { "OC12",    4*155.52 , 3*155.52  , 5*155.52  },
    { "OC48",    16*155.52, 12*155.52 , 20*155.52 },
    { "OC192",   48*155.52, 36*155.52 , 54*155.52 }
};

const MultiQ::BandwidthSpec *
MultiQ::closest_common_bandwidth(double bandwidth)
{
    for (const BandwidthSpec *bw = bandwidth_spec; bw < bandwidth_spec + NBANDWIDTH_SPEC; bw++)
	if (bw->range_lo < bandwidth && bandwidth < bw->range_hi)
	    return bw;
    return 0;
}

MultiQ::Capacity::Capacity(MultiQType type, double scale_, double ntt_)
    : scale(scale_), ntt(ntt_)
{
    if (type == MQ_DATA)
	bandwidth = 1500*8 / ntt, bandwidth52 = 52*8 / ntt;
    else
	bandwidth = 1552*8 / ntt, bandwidth52 = 52*8 / ntt;

    if (const BandwidthSpec *bw = closest_common_bandwidth(bandwidth)) {
	common_bandwidth = bw->bandwidth;
	common_bandwidth_name = bw->name;
    } else {
	common_bandwidth = bandwidth;
	common_bandwidth_name = "?";
    }
    if (const BandwidthSpec *bw = closest_common_bandwidth(bandwidth52)) {
	common_bandwidth52 = bw->bandwidth;
	common_bandwidth52_name = bw->name;
    } else {
	common_bandwidth52 = bandwidth52;
	common_bandwidth52_name = "?";
    }
}

namespace {
struct ModeProbCompar {
    const MultiQ::Histogram &h;
    ModeProbCompar(const MultiQ::Histogram &hh) : h(hh) { }
    inline bool operator()(int a, int b) {
	return h.prob(a) < h.prob(b);
    }
};
}



// MultiQ algorithm  //
//                   //

double
MultiQ::modes2ntt(MultiQType type, const Histogram &h, const Vector<int> &modes) const
{
    Vector<double> gaps;

    double last_x = 0;		// insert artificial mode at 0
    double min_gap = 1e15;

    // Ignore the leftmost mode if we're looking at acks
    const int *modes_begin = modes.begin();
    if (type == MQ_ACK)
	last_x = h.mode_pos(*modes_begin), modes_begin++;

    for (const int *m = modes_begin; m < modes.end(); m++) {
	double x = h.mode_pos(*m);
	if (x >= 0) {
	    double gap = x - last_x;
	    int n = (int)(h.prob(*m) * 1000);
	    gaps.resize(gaps.size() + n, gap);
	    min_gap = std::min(gap, min_gap);
	    last_x = x;
	}
    }

    if (gaps.size() == 0)
	return -1;

    std::sort(gaps.begin(), gaps.end());
    assert(gaps.back() < INTERARRIVAL_CUTOFF);

    Histogram gap_h;
    gap_h.make_kde_sorted(gaps.begin(), gaps.end(), 0.4*min_gap);

    Vector<int> gap_modes;
    gap_h.modes(GAP_SIGNIFICANCE, GAP_MIN_POINTS, gap_modes);

    // if the first mode in the list is tallest, return it
    if (gap_modes.size() >= 1
	&& std::max_element(gap_modes.begin(), gap_modes.end(), ModeProbCompar(gap_h)) == gap_modes.begin())
	return gap_h.mode_pos(gap_modes[0]);
    else
	return -1;
}

double
MultiQ::adjust_max_scale(MultiQType type, const double *begin, const double *end, double tallest_mode_min_scale) const
{
    double next_scale = tallest_mode_min_scale / 2.;

    Histogram hh;
    hh.make_kde_sorted(begin, end, next_scale);

    Vector<int> next_modes;
    hh.modes(SIGNIFICANCE, MIN_POINTS, next_modes);

    // Ignore the leftmost mode if we're looking at acks.
    int *next_modes_start = next_modes.begin();
    if (type == MQ_ACK && next_modes_start < next_modes.end())
	next_modes_start++;

    int *tallest_ptr = std::max_element(next_modes_start, next_modes.end(), ModeProbCompar(hh));
    double tallest_mode_next_scale = (tallest_ptr < next_modes.end() ? hh.mode_pos(*tallest_ptr) : -1);

    return std::min(std::max(tallest_mode_min_scale, tallest_mode_next_scale), MAX_SCALE);
}

void
MultiQ::create_capacities(MultiQType type, const double *begin, const double *end, Vector<Capacity> &capacities) const
{
    // remove too-large values
    while (end > begin && end[-1] >= INTERARRIVAL_CUTOFF)
	end--;

    // exit early if no useful interarrivals
    if (begin >= end)
	return;

    double max_scale = MAX_SCALE;
    bool max_scale_adjusted = false;
    int last_nmodes = INT_MAX;
    double last_ntt = 0;

    for (double scale = MIN_SCALE; scale < max_scale; ) {
	// compute kernel PDF
	Histogram h;
	h.make_kde_sorted(begin, end, scale);

	// find modes
	Vector<int> modes;
	h.modes(SIGNIFICANCE, MIN_POINTS, modes);

	// if no modes, increase scale and continue
	if (modes.size() == 0) {
	    scale *= SCALE_STEP_NOMODES;
	    continue;
	}

	// clean up tiny modes
	{
	    int max_prob_mode = *std::max_element(modes.begin(), modes.end(), ModeProbCompar(h));

	    // adjust max_scale
	    if (!max_scale_adjusted) {
		// If we're looking at acks, then we want to ignore the
		// leftmost mode when adjusting max_scale.
		int max_prob_mode2 = max_prob_mode;
		if (type == MQ_ACK && max_prob_mode == modes[0] && modes.size() > 1)
		    max_prob_mode2 = *std::max_element(modes.begin() + 1, modes.end(), ModeProbCompar(h));

		max_scale = adjust_max_scale(type, begin, end, h.mode_pos(max_prob_mode2));
		max_scale_adjusted = true;
	    }

	    double threshold = 0.01 * h.prob(max_prob_mode);
	    int *out = modes.begin();
	    for (int *x = modes.begin(); x < modes.end(); x++)
		if (h.prob(*x) >= threshold)
		    *out++ = *x;
	    modes.erase(out, modes.end());
	}

	// check for capacity
	if (modes.size() > last_nmodes) {
	    // skip if number of modes is increasing (odd behavior)
	    scale *= SCALE_STEP;

	} else if (modes.size() == 1) {
	    // output this final mode, if it's significantly different from
	    // last capacity mode
	    double ntt = h.mode_pos(modes[0]);
	    if ((ntt - last_ntt) / (ntt + last_ntt) > MODES_SIMILAR)
		capacities.push_back(Capacity(type, scale, ntt));
	    break;

	} else if (modes.size() == 2 && scale < MAX_SCALE/4) {
	    // try and resolve two modes into one if at a smallish scale
	    scale *= SCALE_STEP;

	} else if (modes.size() == 2) {
	    // end if two modes at a large scale
	    // output a heuristic combination of the modes
	    double x1 = h.mode_pos(modes[0]), h1 = h.prob(modes[0]);
	    double x2 = h.mode_pos(modes[1]), h2 = h.prob(modes[1]);

	    // first mode if it is pretty large probability
	    if (h1 > 0.25*h2
		&& (x1 - last_ntt) / (x1 + last_ntt) > MODES_SIMILAR) {
		capacities.push_back(Capacity(type, scale, x1));
		last_ntt = x1;
	    }

	    // second mode if it is very large probability; or it is
	    // relatively large probability, and at a distance, but not
	    // extremely far away
	    double relative_dist = (x2 - x1) / x1;
	    if ((h2 > 2*h1	// very large probability
		 || (h2 > 0.7*h1 // large probability
		     && !(0.985 < relative_dist && relative_dist < 1.015)
				// at a distance
		     && (x2 - x1) < 3*x1)) // not extremely far away
		&& (x2 - last_ntt) / (x2 + last_ntt) > MODES_SIMILAR) {
		capacities.push_back(Capacity(type, scale, x2));
	    }

	    break;

	} else {
	    double ntt = modes2ntt(type, h, modes);
	    if (ntt >= 0 && (ntt - last_ntt) / (ntt + last_ntt) > MODES_SIMILAR) {
		capacities.push_back(Capacity(type, scale, ntt));
		last_ntt = ntt;
		scale = std::max(ntt, scale) * SCALE_STEP;
	    } else
		scale *= SCALE_STEP;
	}
    }
}

void
MultiQ::filter_capacities(Vector<Capacity> &capacities) const
{
    std::reverse(capacities.begin(), capacities.end());
    bool flag = false;
    double last_bandwidth = 0;
    Capacity *out = capacities.begin();
    for (Capacity *n = capacities.begin(); n < capacities.end(); n++) {
	if (30 < n->ntt && n->ntt < 46 && flag)
	    continue;
	if ((100 < n->ntt && n->ntt < 170)
	    || (950 < n->ntt && n->ntt < 1350))
	    flag = true;
	if (n->ntt > n->scale && n->common_bandwidth != last_bandwidth) {
	    *out++ = *n;
	    last_bandwidth = n->common_bandwidth;
	}
    }
    capacities.erase(out, capacities.end());
}

void
MultiQ::run(MultiQType type, Vector<double> &interarrivals, Vector<Capacity> &capacities) const
{
    std::sort(interarrivals.begin(), interarrivals.end());
    create_capacities(type, interarrivals.begin(), interarrivals.end(), capacities);
    filter_capacities(capacities);
}



// Element setup     //
//                   //

MultiQ::MultiQ()
    : INTERARRIVAL_CUTOFF(35000),
      MIN_SCALE(10),
      MAX_SCALE(10000),
      SCALE_STEP(1.1),
      SCALE_STEP_NOMODES(1.5),
      SIGNIFICANCE(2),
      MIN_POINTS(10),
      GAP_SIGNIFICANCE(1),
      GAP_MIN_POINTS(2),
      MODES_SIMILAR(0.05)
{
}

MultiQ::~MultiQ()
{
}

int
MultiQ::configure(Vector<String> &conf, ErrorHandler *errh)
{
    TCPCollector *tcpc = 0;
    bool raw_timestamp = false;
    if (Args(conf, this, errh)
	.read("TCPCOLLECTOR", ElementCastArg("TCPCollector"), tcpc)
	.read("RAW_TIMESTAMP", raw_timestamp)
	.read("MIN_SCALE", MIN_SCALE)
	.complete() < 0)
	return -1;
    if (tcpc)
	tcpc->add_stream_xmltag("multiq_capacity", multiqcapacity_xmltag, this);
    _thru_last = (raw_timestamp ? -2. : -1.);
    return 0;
}

bool
MultiQ::significant_flow(const TCPCollector::Stream* stream, const TCPCollector::Conn* conn) const
{
    double duration = conn->duration().doubleval();
    uint32_t data_packets = stream->total_packets - stream->ack_packets;
    return (data_packets >= 50
	    && data_packets / duration >= 9.5
	    && stream->mtu == 1500);
}

void
MultiQ::multiqcapacity_xmltag(FILE* f, TCPCollector::Stream* stream, TCPCollector::Conn* conn, const String& tagname, void* thunk)
{
    MultiQ *mq = static_cast<MultiQ *>(thunk);

    bool significant = mq->significant_flow(stream, conn);
    bool ack_significant = (!significant && mq->significant_flow(conn->ack_stream(stream), conn));

    if (significant || ack_significant) {
	// collect interarrivals
	Vector<double> interarrivals;
	for (const TCPCollector::Pkt *k = stream->pkt_head->next; k; k = k->next)
	    interarrivals.push_back((k->timestamp - k->prev->timestamp).doubleval() * 1000000);

	// run MultiQ
	Vector<Capacity> capacities;
	mq->run(significant ? MQ_DATA : MQ_ACK, interarrivals, capacities);

	// print results
	for (Capacity *c = capacities.begin(); c < capacities.end(); c++)
	    fprintf(f, "    <%s type='%s' scale='%.1f' time='%.3f' bandwidth='%.3f' commonbandwidth='%.3f' commontype='%s' bandwidth52='%.3f' commonbandwidth52='%.3f' commontype52='%s' />\n",
		    tagname.c_str(), (significant ? "data" : "ack"),
		    c->scale, c->ntt,
		    c->bandwidth, c->common_bandwidth, c->common_bandwidth_name,
		    c->bandwidth52, c->common_bandwidth52, c->common_bandwidth52_name);
    }
}

Packet *
MultiQ::simple_action(Packet *p)
{
    double time = p->timestamp_anno().doubleval() * 1000000.;
    if (_thru_last == -2.)
	_thru_interarrivals.push_back(time);
    else {
	if (_thru_last >= 0)
	    _thru_interarrivals.push_back(time - _thru_last);
	_thru_last = time;
    }
    return p;
}

String
MultiQ::read_capacities(Element *e, void *thunk)
{
    MultiQ *mq = static_cast<MultiQ *>(e);
    StringAccum sa;
    sa << "    w     NTT (us)  1500-BW    40-BW (1500-BW) (40-BW)\n";

    Vector<Capacity> capacities;
    mq->run(thunk ? MQ_ACK : MQ_DATA, mq->_thru_interarrivals, capacities);

    for (Capacity *c = capacities.begin(); c < capacities.end(); c++)
	sa.snprintf(1024, "%6.1f %9.3f  %8.3f %8.3f %8.3f %8.3f\n",
		    c->scale, c->ntt, c->bandwidth, c->bandwidth52,
		    c->common_bandwidth, c->common_bandwidth52);

    return sa.take_string();
}

void
MultiQ::add_handlers()
{
    if (ninputs() > 0) {
	add_read_handler("capacities", read_capacities, 0);
	add_read_handler("ack_capacities", read_capacities, (void *)1);
    }
}



/****************
 * HISTOGRAM    *
 *              *
 ****************/

static inline double
kde_kernel(double x)		// biweight
{
    double f = 1 - x*x;
    return 0.9375*f*f;
    // return 0.75 * (1 - x*x); // epanechikov
}

void
MultiQ::Histogram::make_kde_sorted(const double *cur_lo, const double *end, const double width, double dx)
{
    assert(cur_lo < end);
    const double width_inverse = 1/width;

    if (dx < 0)
	dx = width / -dx;

    _left = cur_lo[0] - width - 1.5*dx;
    int nbins = (int)((end[-1] + width + 1.5*dx - _left) / dx) + 3;
    _bin_width = dx;		// k->dx
    _kde_width = width;		// k->wmin

    _nitems = end - cur_lo;
    const double *cur_hi = cur_lo;

    // first bin is always empty
    _count.assign(1, 0);

    for (int i = 1; i < nbins; i++) {
	double binpos = mode_pos(i);

	while (cur_lo < end && *cur_lo < binpos - width)
	    cur_lo++;
	while (cur_hi < end && *cur_hi < binpos + width)
	    cur_hi++;

	double p = 0;
	for (const double *cur = cur_lo; cur < cur_hi; cur++)
	    p += kde_kernel((*cur - binpos) * width_inverse);
	_count.push_back(p);
	/* NOTE: must multiply _count[] by dx / w to get proper CDF */
    }
}

/* A mode is the highest point in any region statistically more likely than one
   before and one after it.  I cannot figure out a way to identify modes in one
   pass.  Gradual mode accumulation confuses such strategies.  So we suck it up
   and do multiple passes -- one to identify all local maxima, one to bracket
   these as significant, another to coalesce duplicates, and a final one to
   emit the proper x-value in each mode. */

namespace {
struct Mode {
    int a, i, b;
    inline Mode(int ii) : a(ii), i(ii), b(ii) { }
};

inline bool
operator<(const Mode &a, const Mode &b)
{
    if (a.i < 0 || b.i < 0)
	return b.i < a.i;
    else if (a.a != b.a)
	return a.a < b.a;
    else if (a.i != b.i)
	return a.i < b.i;
    else
	return a.b < b.b;
}
}

void
MultiQ::Histogram::modes(double significance, double min_points, Vector<int> &mode_indexes) const
{
    assert(min_points > 0);
    Vector<Mode> modes;

    // collect local maxima in 'modes' array
    double last_delta = -1;
    for (int bin = 1; bin < _count.size(); bin++) {
	double delta = _count[bin] - _count[bin - 1];
	if (delta < 0 && last_delta >= 0 && _count[bin] >= min_points)
	    modes.push_back(Mode(bin - 1));
	last_delta = delta;
    }

    // bracket each mode by expanding (a,b)
    for (Mode *m = modes.begin(); m < modes.end(); m++) {
	double p0 = kde_prob(m->i);
	double p_thresh = std::max(p0 - significance * kde_sig_prob(m->i), 0.0);

	for (m->a = m->i - 1; m->a >= 0 && kde_prob(m->a) > p_thresh; m->a--)
	    if (kde_prob(m->a) > p0) // earlier max with no dip
		goto kill_this_mode;
	for (m->b = m->i + 1; m->b < _count.size() && kde_prob(m->b) > p_thresh; m->b++)
	    if (kde_prob(m->b) > p0) // later max with no dip
		goto kill_this_mode;
	continue;

      kill_this_mode:
	m->i = -1;
    }

    // coalesce overlapping modes into "mode of modes" (i.e. tallest)
    {
	std::sort(modes.begin(), modes.end());
	Mode *m = modes.begin();
	// We sorted dead modes to the end of the list, so exit when we
	// encounter one.  (We kill some modes ourselves, but we skip them
	// right away.)
	for (Mode *next_m = m + 1; next_m < modes.end() && next_m->i >= 0; next_m++) {
	    if (next_m->i < m->b) { // next mode inside
		if (kde_prob(next_m->i) > kde_prob(m->i))
		    m->i = next_m->i;
		if (next_m->b > m->b)
		    m->b = next_m->b;
		next_m->i = -1;
	    } else
		m = next_m;
	}
    }

    // sort modes in decreasing order of importance
    for (Mode *m = modes.begin(); m < modes.end(); m++)
	if (m->i >= 0)
	    mode_indexes.push_back(m->i);
}

#if 0
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
    int max_bin = (int)((end[-1] - _left) / _bin_width);
    if (max_bin >= _count.size())
	_count.resize(max_bin + 1, (_count.size() ? _count.back() : 0));
    _nitems += end - cur;

    // sweep through
    for (int bin = 0; bin < _count.size(); bin++) {
	double br = pos(bin + 1);
	const double *first = cur;
	while (cur < end && *cur < br)
	    cur++;
	_count[bin] += cur - first;
    }
}
#endif


ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(MultiQ)
CLICK_ENDDECLS
