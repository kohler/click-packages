#include <config.h>
#include <click/config.h>

#include "calculatevariance.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <packet_anno.hh>


CalculateVariance::CalculateVariance()
    : Element(1,1)
{
    MOD_INC_USE_COUNT;
}

CalculateVariance::~CalculateVariance()
{
    MOD_DEC_USE_COUNT;
}

int
CalculateVariance::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    bool _bits = false;

    _interval.tv_sec = 0;
    _interval.tv_usec = 0;
    _num_aggregates = 1024;

    if (cp_va_parse(conf, this, errh,
		    cpTimeval, "interval in struct timeval", &_interval,
		    cpUnsigned, "number of aggregates (in bits) expected", &_num_aggregates_bits,
		    0) < 0) 
	return -1;

    _num_aggregates = 1 << _num_aggregates_bits;
    _counters.resize(_num_aggregates);

    return 0;
}

void
CalculateVariance::reset()
{
   //reset all counters in the table
   end_time.tv_sec = 0;
   end_time.tv_usec = 0;

   num_intervals = 0;

   for (int i=0;i<_counters.size();i++) {
       _counters[i].init(i);
   }
}

int
CalculateVariance::initialize(ErrorHandler *)
{
    _total_pkts = 0;
    reset();
    return 0;
}

Packet *
CalculateVariance::simple_action(Packet *p)
{
    int row = AGGREGATE_ANNO(p);

    if (_num_aggregates == 1) row = 0;

    if ((end_time.tv_sec == 0) && (end_time.tv_usec == 0)) {
	timeradd(&p->timestamp_anno(),&_interval,&end_time);
    }

    if ((row<0) || (row>_num_aggregates)) {

	click_chatter("aggregate %d is bigger than reserved value! counter resized!",row);
	_counters.resize(row+1);
	_num_aggregates = row+1;

    }
    
    if(timercmp(&p->timestamp_anno(),&end_time,>)) {
	for (int i=0;i<_counters.size();i++) {
	    _counters[i].pkt_sum += _counters[i].pkt_sum_interval;
	    _counters[i].pkt_sum_sq += _counters[i].pkt_sum_interval * _counters[i].pkt_sum_interval;
	    _counters[i].pkt_sum_interval = 0;
	}

	timeradd(&p->timestamp_anno(), &_interval, &end_time);
	num_intervals++;
    }

    _counters[row].pkt_sum_interval++;
    _counters[row].pkt_count++;
    _counters[row].byte_count += p->length();

    _total_pkts++;

    return p;
}

double
CalculateVariance::get_variance(int row)
{
    if ((row<0)||(row>=_num_aggregates)) {
	click_chatter("no such aggregate %d!",row);
	return 0.0;
    }else if (num_intervals<=0) {
	click_chatter("number of intervals is zero for row %d!",row);
	return 0.0;
    }else {
	return _counters[row].get_pkt_variance(num_intervals);
    }

}

void
CalculateVariance::print_all_variance()
{
    for (int i=0;i<_counters.size();i++) {
       printf("agg no: %d var: %.2f num intevals: %d pkt_sum %d pkt_sum_sq %d pkt_count %d\n",i,get_variance(i),num_intervals,_counters[i].pkt_sum,_counters[i].pkt_sum_sq,_counters[i].pkt_count);
    }
}

static int pktsorter(const void *av, const void *bv) {
    const CalculateVariance::CounterEntry *a = (const CalculateVariance::CounterEntry *)av, *b = (const CalculateVariance::CounterEntry *)bv;
    return a->pkt_count - b->pkt_count;
}

void
CalculateVariance::print_edf_function()
{
    String _filename;

    _filename = String(_num_aggregates_bits) + "-bit-agg";
    FILE *outfile = fopen(_filename.cc(), "w");
    if (!outfile) {
        click_chatter("%s: %s", _filename.cc(), strerror(errno));
	return;
    }
   
    fprintf(outfile,"#total number of packets %lld \n",_total_pkts);
    //to get edf i need to first sort the data
    qsort(&_counters[0],_counters.size(),sizeof(CounterEntry),&pktsorter);

    double step = (double) 1/_num_aggregates;
    unsigned prev_edf_x_size = _counters[0].pkt_count;
    unsigned prev_count = 0;
    double edf_y_val = step;

    assert(_num_aggregates == _counters.size());
    int i=1;

    do {
	if ((i==_counters.size()) || ((_counters[i].pkt_count!=prev_edf_x_size))) {
	    fprintf(outfile,"%d\t %0.10f \t(%d)",prev_edf_x_size,edf_y_val,i-prev_count);
	    if ((i-prev_count)<10) {
		for (int j=prev_count;j<i;j++) {
		    fprintf(outfile,"\t%d",_counters[j].aggregate_no);
		}
	    }
	    fprintf(outfile,"\n");
	    if (i<_counters.size()) prev_edf_x_size = _counters[i].pkt_count;
	    prev_count = i;
	}
	edf_y_val += step;
	i++;

    }while (i<=_counters.size());

    if (fclose(outfile)) {
	click_chatter("error closing file!");
    }
}

static String
calculatevariance_read_variance_handler(Element *e, void *thunk)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    int row = (int)thunk;
    return String(cv->get_variance(row)) + "\n";
}

static String
calculatevariance_print_all_variance_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_all_variance();
    return String("\n");
}

static String
calculatevariance_print_edf_function_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_edf_function();
    return String("\n");
}

static int
calculatevariance_reset_write_handler (const String &, Element *e, void *, ErrorHandler *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->reset();
    return 0;
}

void
CalculateVariance::add_handlers()
{
    add_read_handler("variance",calculatevariance_read_variance_handler,0);
    add_read_handler("printallvariance",calculatevariance_print_all_variance_handler,0);
    add_read_handler("printEDFfunction",calculatevariance_print_edf_function_handler,0);
    add_write_handler("reset",calculatevariance_reset_write_handler,0);
}

EXPORT_ELEMENT(CalculateVariance)

#include <click/vector.cc>
