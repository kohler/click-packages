// -*- c-basic-offset: 4 -*-
#include <click/config.h>
#include "multiq.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <float.h>
#include <algorithm>
CLICK_DECLS


static inline double
kde_kernel(double x)		// biweight
{
    return 0.9375*(1 - x*x)*(1 - x*x);
    // return 0.75 * (1 - x*x); // epanechikov
}

void
Histogram::make_kde_sorted(const double *cur_lo, const double *end, const double width, double dx)
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
	double binpos = pos(i + 0.5);
	
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
Histogram::modes(double significance, double min_points, Vector<int> &mode_indexes) const
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
	double p0 = prob(m->i);
	double p_thresh = std::max(p0 - significance * sig_prob(m->i), 0.0);

	for (m->a = m->i - 1; m->a >= 0 && prob(m->a) > p_thresh; m->a--)
	    if (prob(m->a) > p0) // earlier max with no dip
		goto kill_this_mode;
	for (m->b = m->i + 1; m->b < _count.size() && prob(m->b) > p_thresh; m->b++)
	    if (prob(m->b) > p0) // later max with no dip
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
		if (prob(next_m->i) > prob(m->i))
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


namespace {
struct ModeProbCompar {
    const Histogram &h;
    ModeProbCompar(const Histogram &hh) : h(hh) { }
    inline bool operator()(int a, int b) {
	return h.prob(a) < h.prob(b);
    }
};
}


/****************
 * MULTIQ       *
 *              *
 ****************/

MultiQ::MultiQ()
    : Element(0, 0),
      INTERARRIVAL_CUTOFF(35000),
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
    MOD_INC_USE_COUNT;
}

MultiQ::~MultiQ()
{
    MOD_DEC_USE_COUNT;
}

int
MultiQ::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *e;
    if (cp_va_parse(conf, this, errh,
		    cpElement, "TCPCollector", &e,
		    0) < 0)
	return -1;
    if (TCPCollector *tcpc = (TCPCollector *)e->cast("TCPCollector")) {
	tcpc->add_stream_xmltag("multiq_capacity", multiqcapacity_xmltag, this);
	return 0;
    } else
	return errh->error("'%s' not a TCPCollector element", e->declaration().c_str());
}

MultiQ::BandwidthSpec MultiQ::bandwidth_spec[MultiQ::NBANDWIDTH_SPEC] = {
    { "modem",   0.056    , 0.000     , 0.064     },
    { "cable",   0.512    , 0.512     , 0.512     },
    { "T1",      1.544    , 1.544     , 1.544     },
    { "10bT",    10       , 7         , 11.7      },
    { "T3",      29*1.544 , 26*1.544  , 32*1.544  },
    { "100bT",   100      , 71        , 120       },
    { "OC3",     155.52   , 130       , 165       },
    { "OC12",    4*155.52 , 3*155.52  , 5*155.52  },
    { "OC48",    16*155.52, 12*155.52 , 20*155.52 },
    { "OC192",   48*155.52, 36*155.52 , 54*155.52 }
};

MultiQ::NTTSpec::NTTSpec(double scale_, double ntt_)
    : scale(scale_), ntt(ntt_)
{
}

double
MultiQ::closest_common_bandwidth(double bandwidth)
{
    for (BandwidthSpec *bw = bandwidth_spec; bw < bandwidth_spec + NBANDWIDTH_SPEC; bw++)
	if (bw->range_lo < bandwidth && bandwidth < bw->range_hi)
	    return bw->bandwidth;
    return bandwidth;
}

const char *
MultiQ::closest_common_type(double bandwidth)
{
    for (BandwidthSpec *bw = bandwidth_spec; bw < bandwidth_spec + NBANDWIDTH_SPEC; bw++)
	if (bw->range_lo < bandwidth && bandwidth < bw->range_hi)
	    return bw->name;
    return "?";
}

double
MultiQ::modes2ntt(const Histogram &h, const Vector<int> &modes) const
{
    Vector<double> gaps;

    double last_x = 0;		// insert artificial mode at 0
    double min_gap = 1e15;
    for (const int *m = modes.begin(); m < modes.end(); m++) {
	double x = h.pos(*m + 0.5);
	if (x >= 0) {
	    double gap = x - last_x;
	    int n = (int)(h.prob(*m) * 1000);
	    gaps.resize(gaps.size() + n, gap);
	    min_gap = std::min(gap, min_gap);
	    last_x = x;
	}
    }

    std::sort(gaps.begin(), gaps.end());
    assert(gaps.back() < INTERARRIVAL_CUTOFF);
    
    Histogram gap_h;
    gap_h.make_kde_sorted(gaps.begin(), gaps.end(), 0.4*min_gap);

    Vector<int> gap_modes;
    gap_h.modes(GAP_SIGNIFICANCE, GAP_MIN_POINTS, gap_modes);

    // if the first mode in the list is tallest, return it
    if (gap_modes.size() >= 1
	&& std::max_element(gap_modes.begin(), gap_modes.end(), ModeProbCompar(gap_h)) == gap_modes.begin())
	return gap_h.pos(gap_modes[0] + 0.5);
    else
	return -1;
}

void
MultiQ::create_ntts(const double *begin, const double *end, Vector<NTTSpec> &out_ntt) const
{
    while (end > begin && end[-1] >= INTERARRIVAL_CUTOFF)
	end--;
    
    int last_nmodes = INT_MAX;
    double last_ntt = 0;
    
    for (double scale = MIN_SCALE; scale < MAX_SCALE; ) {
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
	    double ntt = h.pos(modes[0] + 0.5);
	    if ((ntt - last_ntt) / (ntt + last_ntt) > MODES_SIMILAR)
		out_ntt.push_back(NTTSpec(scale, ntt));
	    break;

	} else if (modes.size() == 2 && scale < MAX_SCALE/4) {
	    // try and resolve two modes into one if at a smallish scale
	    scale *= SCALE_STEP;
	    
	} else if (modes.size() == 2) {
	    // end if two modes at a large scale
	    // output a heuristic combination of the modes
	    double x1 = h.pos(modes[0] + 0.5), h1 = h.prob(modes[0]);
	    double x2 = h.pos(modes[1] + 0.5), h2 = h.prob(modes[1]);

	    // first mode if it is pretty large probability
	    if (h1 > 0.25*h2
		&& (x1 - last_ntt) / (x1 + last_ntt) > MODES_SIMILAR) {
		out_ntt.push_back(NTTSpec(scale, x1));
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
		out_ntt.push_back(NTTSpec(scale, x2));
	    }

	    break;

	} else {
	    double ntt = modes2ntt(h, modes);
	    if (ntt >= 0 && (ntt - last_ntt) / (ntt + last_ntt) > MODES_SIMILAR) {
		out_ntt.push_back(NTTSpec(scale, ntt));
		last_ntt = ntt;
		scale = std::max(ntt, scale) * SCALE_STEP;
	    } else
		scale *= SCALE_STEP;
	}
    }
}

void
MultiQ::filter_ntts(Vector<NTTSpec> &ntts) const
{
    std::reverse(ntts.begin(), ntts.end());
    bool flag = false;
    double last_bandwidth = 0;
    NTTSpec *out = ntts.begin();
    for (NTTSpec *n = ntts.begin(); n < ntts.end(); n++) {
	if (30 < n->ntt && n->ntt < 46 && flag)
	    continue;
	if ((100 < n->ntt && n->ntt < 170)
	    || (950 < n->ntt && n->ntt < 1350))
	    flag = true;
	if (n->ntt > n->scale) {
	    double bandwidth = closest_common_bandwidth(1500*8 / n->ntt);
	    if (bandwidth != last_bandwidth) {
		*out++ = *n;
		last_bandwidth = bandwidth;
	    }
	}
    }
    ntts.erase(out, ntts.end());
}

bool
MultiQ::significant_flow(const TCPCollector::StreamInfo &stream, const TCPCollector::ConnInfo &conn) const
{
    double duration = timeval2double(conn.duration());
    uint32_t data_packets = stream.total_packets - stream.ack_packets;
    return (data_packets >= 50
	    && data_packets / duration >= 9.5
	    && stream.mtu == 1500);
}

void
MultiQ::multiqcapacity_xmltag(FILE *f, const TCPCollector::StreamInfo &stream, const TCPCollector::ConnInfo &conn, const String &tagname, void *thunk)
{
    MultiQ *mq = static_cast<MultiQ *>(thunk);
    if (mq->significant_flow(stream, conn)) {
	// collect interarrivals
	Vector<double> interarrivals;
	for (const TCPCollector::Pkt *k = stream.pkt_head->next; k; k = k->next)
	    interarrivals.push_back(timeval2double(k->timestamp - k->prev->timestamp) * 1000000);
	std::sort(interarrivals.begin(), interarrivals.end());

	// run MultiQ
	Vector<NTTSpec> ntts;
	mq->create_ntts(interarrivals.begin(), interarrivals.end(), ntts);
	mq->filter_ntts(ntts);

	// print results
	for (NTTSpec *ntt = ntts.begin(); ntt < ntts.end(); ntt++)
	    fprintf(f, "    <%s scale='%g' time='%g' bandwidth='%g' commonbandwidth='%g' commontype='%s' bandwidth52='%g' commonbandwidth52='%g' commontype52='%s' />\n",
		    tagname.c_str(), ntt->scale, ntt->ntt,
		    1500*8/ntt->ntt, closest_common_bandwidth(1500*8/ntt->ntt), closest_common_type(1500*8/ntt->ntt),
		    52*8/ntt->ntt, closest_common_bandwidth(52*8/ntt->ntt), closest_common_type(52*8/ntt->ntt));
    }
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


#include <click/vector.cc>
ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(MultiQ)
CLICK_ENDDECLS



#if 0
#include <iostream>
#include <fstream>
using namespace std;

static void
print_pdf(const Histogram &h, std::ostream &stream)
{
    stream << h.pos(-0.1) << " 0\n";
    for (int i = 0; i < h.size(); i++)
	stream << h.pos(i) << " " << h.prob(i) << '\n';
    // NB: This gives results that are off by one relative to 'lade', since
    // 'lade' prints, for bin "i", the number of elements that were stored
    // in bin "i+1".
}

int
main(int, char **)
{
    Vector<double> nums;
    double num;
    while (cin >> num)
	nums.push_back(num);
    std::sort(nums.begin(), nums.end());
    
    // -b 35000: censor points past 35000  (b)
    // -Y4: insist on at least 4 points to count as a mode  (Y)
    // -ekb: KRN, kde_biweight
    // -em2: modes, sds==2
    // -N2: nrm_mode==2
    // -w100: w==100

    while (nums.size() && nums.back() >= 35000)
	nums.pop_back();
    
    Histogram h;
    h.make_kde_sorted(nums.begin(), nums.end(), 100, -18);
    // w, g are the args

    cout.precision(17);

    ofstream pdfo("out.krn2");
    print_pdf(h, pdfo);
    
    Vector<int> modes;
    h.modes(2, 4, modes);
    for (int i = 0; i < modes.size(); i++)
	cout << h.pos(modes[i]+0.5) << ' ' << h.prob(modes[i]) << '\n';

    return 0;
}
#endif

