#ifndef CALCULATEVARIANCE_HH
#define CALCULATEVARIANCE_HH

#include <click/element.hh>
#include <click/glue.hh>

/* counts the variance of # of packets over intevals of _inteval size
 *                     or bytes over intevals of _inteval size
 * a simple usage
 *
 * FromTUSummaryLog("file",STOP true) 
 * -> va1::CalculateVariance(0.01)
 * -> va2::CalculateVariance(0.1)
 * ->Discard;
 */


class CalculateVariance : public Element {

    struct timeval _interval;
    struct timeval _end_time;
    unsigned _num_intervals;

    public:
    CalculateVariance();
    ~CalculateVariance();

    const char *class_name() const { return "CalculateVariance";}
    CalculateVariance *clone() const { return new CalculateVariance; }
    const char *processing() const { return AGNOSTIC; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void add_handlers();

    double variance(int) const;
    uint32_t packet_count(int i) const	{ return _counters[i].pkt_count; }

    Packet *simple_action(Packet *);
    void reset();
    void print_all_variance(); 
    void print_edf_function();

    class CounterEntry {
	public:
	CounterEntry():pkt_sum_interval(0),pkt_sum(0),pkt_sum_sq(0),pkt_count(0),byte_count(0) {}
	double get_pkt_variance(unsigned num_int) const {
	    assert(num_int>0);
	    double tmp_mean_sqr = (double) pkt_sum/num_int;
	    tmp_mean_sqr = tmp_mean_sqr * tmp_mean_sqr;
	    return ((double)pkt_sum_sq/num_int) - tmp_mean_sqr;
	}

	unsigned pkt_sum_interval; //number of packets accumulated in the current (unfinished) interval
	unsigned pkt_sum; // Sum(X) where X is ther number of packets in the previous intervals.
	unsigned pkt_sum_sq; //Sum(X^2) where X is ther number of packets in the previous intervals. var(X) = E(X^2) - E(X)^2;
	uint32_t pkt_count;
	unsigned byte_count;
	
	/*
	double pkt_bytes_sum;
	double pkt_bytes_sum_sq;
	double pkt_bytes_sum_interval; 
	*/
    };

    Vector<CounterEntry> _counters;
    unsigned _num_aggregates;
    unsigned _num_aggregates_bits;
    unsigned long long int _total_pkts;

};

#endif
