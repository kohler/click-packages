#ifndef TRACEINFO_HH
#define TRACEINFO_HH

#include <click/element.hh>
#include <click/glue.hh>
#include <click/bighashmap.hh>

/* counts the variance of # of packets over intevals of _inteval size
 *                     or bytes over intevals of _inteval size
 * a simple usage
 *
 * FromTUSummaryLog("file",STOP true) 
 * -> t::TraceInfo("general-verio","master-verio")
 * ->Discard;
 */


class TraceInfo: public Element {

    struct timeval _start_time;
    struct timeval _end_time;

    public:
    TraceInfo();
    ~TraceInfo();

    const char *class_name() const { return "TraceInfo";}
    TraceInfo *clone() const { return new TraceInfo; }
    const char *processing() const { return AGNOSTIC; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void add_handlers();

    Packet *simple_action(Packet *);
    void reset();
    void print_master_file();
    void print_general_file();

    unsigned long long int _total_pkts;
    double _total_bytes;
    typedef BigHashMap<unsigned, unsigned> counter_table;
    counter_table _hashed_counters;

    String _generaloutfilename;
    String _masteroutfilename;

};

#endif
