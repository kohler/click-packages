#ifndef ONOFFMODEL_HH
#define ONOFFMODEL_HH

#include <click/element.hh>
#include <click/glue.hh>
#include <click/bighashmap.hh>

class OnOffModel : public Element {

    public:
    OnOffModel();
    ~OnOffModel();

    const char *class_name() const { return "OnOffModel";}
    OnOffModel *clone() const {return new OnOffModel;}
    const char *processing() const { return AGNOSTIC;}

    int configure(const Vector<String> &, ErrorHandler *);
    void add_handlers();

    class OnOffConnCounter{

	public:
	OnOffConnCounter() {}
	OnOffConnCounter(struct timeval stime, unsigned int pkt_c, unsigned int byte_c)
	    : total_on_throughput(0.0),total_on_throughput_sqr(0.0),total_on_transfers(0),
	      total_off_duration(0.0),total_off_duration_sqr(0.0),total_off_times(0) 
	{

	    start_time = stime;
	    end_time = stime;
	    pkt_counts = pkt_c;
	    byte_counts = byte_c;

	}

	struct timeval start_time;
	struct timeval end_time;
	unsigned int pkt_counts;
	unsigned int byte_counts;

	double total_on_throughput;
	double total_on_throughput_sqr;
	unsigned int total_on_transfers;

	double total_off_duration;
	double total_off_duration_sqr;
	unsigned int total_off_times;

    };

    typedef BigHashMap<IPAddress, OnOffConnCounter> onoff_countertable;
    onoff_countertable _hashed_counters;
    struct timeval _max_silence_int;

    Packet *simple_action(Packet *);
    int write_file(String,ErrorHandler *) const;
    int write_file_handler(const String &,Element *, void *, ErrorHandler *);

};

#endif
