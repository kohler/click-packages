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
    _interval.tv_sec = 0;
    _interval.tv_usec = 0;
    _num_aggregates = 1024;
    if (cp_va_parse(conf, this, errh,
		    cpTimeval, "interval in struct timeval", &_interval,
		    cpUnsigned, "number of aggregates expected", &_num_aggregates,
		    0) < 0) return -1;
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
       _counters[i].init();
   }
}

int
CalculateVariance::initialize(ErrorHandler *)
{

    reset();
    return 0;
}

Packet *
CalculateVariance::simple_action(Packet *p)
{
    int row = AGGREGATE_ANNO(p);

    if ((end_time.tv_sec == 0) && (end_time.tv_usec == 0)) {
	timeradd(&p->timestamp_anno(),&_interval,&end_time);
    }

    if ((row<0) || (row>_num_aggregates)) {

	click_chatter("aggregate %d is bigger than reserved value! counter resized!",row);
	_counters.resize(row+1);
	_num_aggregates = row+1;

    }else if(timercmp(&p->timestamp_anno(),&end_time,>)) {
	for (int i=0;i<_counters.size();i++) {
	    _counters[i].pkt_sum += _counters[i].pkt_sum_interval;
	    _counters[i].pkt_sum_sq += _counters[i].pkt_sum_interval * _counters[i].pkt_sum_interval;
	    _counters[i].pkt_sum_interval = 0;
	}

	timeradd(&p->timestamp_anno(), &_interval, &end_time);
	num_intervals++;
    }

    _counters[row].pkt_sum_interval++;

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
       printf("agg no: %d var: %.2f num intevals: %d pkt_sum %d pkt_sum_sq %d\n",i,get_variance(i),num_intervals,_counters[i].pkt_sum,_counters[i].pkt_sum_sq);
    }
}


static String
calculatevariance_read_variance_handler(Element *e, void *thunk)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    int row = (int)thunk;
    return String(cv->get_variance(row)) + "\n";
}

static int
calculatevariance_reset_write_handler (const String &, Element *e, void *, ErrorHandler *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->reset();
    return 0;
}

static String
calculatevariance_print_all_variance_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_all_variance();
    return String("\n");
}

void
CalculateVariance::add_handlers()
{
    add_read_handler("variance",calculatevariance_read_variance_handler,0);
    add_read_handler("printallvariance",calculatevariance_print_all_variance_handler,0);
    add_write_handler("reset",calculatevariance_reset_write_handler,0);
}

EXPORT_ELEMENT(CalculateVariance)

#include <click/vector.cc>
