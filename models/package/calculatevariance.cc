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
    bool bits = false;
    unsigned naggregates = 1024;
    _interval.tv_sec = 0;
    _interval.tv_usec = 0;
    _use_hash = false;

    if (cp_va_parse(conf, this, errh,
		    cpTimeval, "interval in struct timeval", &_interval,
		    cpUnsigned, "number of aggregates expected", &naggregates,
		    cpFilename, "filename for output",&_outfilename,
		    cpKeywords,
		    "BITS", cpBool, "number of aggregates is in bits?", &bits,
		    "USEHASH",cpBool,"use hash table for classifying aggregates?",&_use_hash,
		    0) < 0) 
	return -1;

    if (bits) {
	_num_aggregates_bits = naggregates;
	if (naggregates > 32)
	    return errh->error("too many aggregates! max 2^32");
	_num_aggregates = 1 << naggregates;
    } else {
	_num_aggregates = naggregates;
	_num_aggregates_bits = 0;
    }

    if (!_use_hash) 
	_counters.resize(_num_aggregates);

    top_aggregates.resize(1024);
    top_agg_index = 0;

    return 0;
}

void
CalculateVariance::reset()
{
   _end_time.tv_sec = 0;
   _end_time.tv_usec = 0;
   _num_intervals = 0;
   _total_pkts = 0;
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

    uint32_t row = AGGREGATE_ANNO(p);

    if (_num_aggregates == 1) row = 0;

    if ((_end_time.tv_sec == 0) && (_end_time.tv_usec == 0)) {
	timeradd(&p->timestamp_anno(),&_interval,&_end_time);
    }

    if (_use_hash) {

	CalculateVariance::CounterEntry *ent = _hashed_counters.findp(row);
	if (!ent) {
	    _hashed_counters.insert(row,CalculateVariance::CounterEntry());
	    ent = _hashed_counters.findp(row);
	}

	if(timercmp(&p->timestamp_anno(),&_end_time,>)) {
	    int total_pkts_in_interval = 0;
	    int max_pkts_in_interval = 0;
	    int top_agg = 0;

	    for (counter_table::Iterator iter = _hashed_counters.first(); iter; iter++) {

		CalculateVariance::CounterEntry e = iter.value();

		//keep track of the top aggregate in this interval
		total_pkts_in_interval += e.pkt_sum_interval;
		if (max_pkts_in_interval < e.pkt_sum_interval) {
		    max_pkts_in_interval = e.pkt_sum_interval;
		    top_agg = iter.key();
		}

		e.pkt_sum += e.pkt_sum_interval;
		e.pkt_sum_sq += (double)e.pkt_sum_interval * e.pkt_sum_interval;
		e.pkt_sum_interval = 0;
	    }

	    //store the top aggregate for this interval
	    top_aggregates[top_agg_index]._which_interval = _end_time;
	    top_aggregates[top_agg_index]._which_agg = top_agg;
	    top_aggregates[top_agg_index]._num_pkts = max_pkts_in_interval;
	    top_aggregates[top_agg_index]._percentage = (double)max_pkts_in_interval/total_pkts_in_interval;
	    top_agg_index++;
	    if (top_agg_index >= top_aggregates.size()) {
		top_aggregates.resize(top_agg_index * 2);
	    }

	    timeradd(&p->timestamp_anno(), &_interval, &_end_time);
	    _num_intervals++;
	}

	ent->pkt_sum_interval++;
	ent->pkt_count++;
	ent->byte_count += p->length();

    }else {

	//the number of aggregates is stored in a vector intead of hash
	if (row>_num_aggregates) {
	    click_chatter("aggregate %d is bigger than reserved value! counter resized!",row);
	    _counters.resize(row+1);
	    _num_aggregates = row+1;
	}
    
	if(timercmp(&p->timestamp_anno(),&_end_time,>)) {
	    for (int i=0;i<_counters.size();i++) {
		_counters[i].pkt_sum += _counters[i].pkt_sum_interval;
		_counters[i].pkt_sum_sq += (double)_counters[i].pkt_sum_interval * _counters[i].pkt_sum_interval;
		_counters[i].pkt_sum_interval = 0;
	    }

	    timeradd(&p->timestamp_anno(), &_interval, &_end_time);
	    _num_intervals++;
	}

	_counters[row].pkt_sum_interval++;
	_counters[row].pkt_count++;
	_counters[row].byte_count += p->length();
    }

    _total_pkts++;
    return p;
}

double
CalculateVariance::variance(int row) const
{
    if ((uint32_t)row >= _num_aggregates) {
	click_chatter("no such aggregate %d!",row);
	return 0.0;
    }else if (_num_intervals<=0) {
	click_chatter("number of intervals is zero for row %d!",row);
	return 0.0;
    }else {
	if (_use_hash) {
	    CounterEntry *e = _hashed_counters.findp(row);
	    if (!e) {
		return 0.0;
	    }else{
		return e->get_pkt_variance(_num_intervals);
	    }
	}else {
	    return _counters[row].get_pkt_variance(_num_intervals);
	}
    }

}

void
CalculateVariance::print_all_variance()
{
    if (_use_hash) {
	for (counter_table::Iterator iter = _hashed_counters.first(); iter; iter++) {
	    CounterEntry e = iter.value();
	    printf("agg no: %d var: %E num intevals: %d pkt_sum %d pkt_sum_sq %f pkt_count %d\n",iter.key(),variance(iter.key()),_num_intervals,e.pkt_sum,e.pkt_sum_sq,e.pkt_count);
	}
    }else{ 
	for (int i=0;i<_counters.size();i++) {
	    printf("agg no: %d var: %E num intevals: %d pkt_sum %d pkt_sum_sq %f pkt_count %d\n",i,variance(i),_num_intervals,_counters[i].pkt_sum,_counters[i].pkt_sum_sq,_counters[i].pkt_count);
	}
    }
}


static CalculateVariance *sorting_cv;

static int pktsorter(const void *av, const void *bv) {
    unsigned a = *((const unsigned *)av);
    unsigned b = *((const unsigned *)bv);
    assert((a >= 0) && (a < sorting_cv->_num_aggregates));
    assert((b>=0)&&(b<sorting_cv->_num_aggregates));
    return sorting_cv->packet_count(a) - sorting_cv->packet_count(b);
}

void
CalculateVariance::print_edf_function()
{

    FILE *outfile = fopen(_outfilename.cc(), "w");
    if (!outfile) {
        click_chatter("%s: %s", _outfilename.cc(), strerror(errno));
	return;
    }
   
    fprintf(outfile,"#total number of packets %lld \n",_total_pkts);
    
    //to get edf i need to first sort the data
    unsigned *permutation;

    ::sorting_cv = this;
    if (_use_hash) {
	permutation = new unsigned[_hashed_counters.size()];
	int i=0;
	for (counter_table::Iterator iter = _hashed_counters.first(); iter; iter++) {
	    permutation[i] = iter.key();
	    CounterEntry ent = iter.value();
	    i++;
	}
	assert(i < _num_aggregates);
	qsort(permutation,i, sizeof(unsigned), &pktsorter);

    }else{
	permutation = new unsigned[_num_aggregates];
	for (unsigned i = 0; i < _num_aggregates; i++)
	    permutation[i] = i;
	qsort(permutation, _num_aggregates, sizeof(unsigned), &pktsorter);

    }


    double step = (double) 1/_num_aggregates;
    unsigned prev_edf_x_size;
    unsigned prev_count = 0;
    double edf_y_val = 0.0;
    unsigned _num_aggregates_save;

    if (_use_hash) {
	edf_y_val = step * (_num_aggregates - _hashed_counters.size());
	fprintf(outfile,"%d\t %0.10f \t(%d)\n",0,edf_y_val,_num_aggregates - _hashed_counters.size());
	prev_edf_x_size = (_hashed_counters.findp((int)permutation[0]))->pkt_count;
	_num_aggregates_save = _num_aggregates;
	_num_aggregates = _hashed_counters.size();

	prev_edf_x_size = (_hashed_counters.findp( permutation[0] ))->pkt_count;

    }else{
	prev_edf_x_size = _counters[ permutation[0] ].pkt_count;
    }

    edf_y_val += step;
     

    unsigned i = 1;
    CounterEntry *entry;

    do {
	if (i < _num_aggregates) {
	    if (_use_hash)
		entry = _hashed_counters.findp(permutation[i]);
	    else
		entry = &(_counters[permutation[i]]);
	}

	if ((i == _num_aggregates)
	    || (entry ->pkt_count != prev_edf_x_size)) {
	    fprintf(outfile,"%d\t %0.10f \t(%d)",prev_edf_x_size,edf_y_val,i-prev_count);
	    if ((i-prev_count)<10) {
		for (unsigned j = prev_count; j < i; j++) {
		    fprintf(outfile,"\t%d", permutation[j]);
		}
	    }
	    fprintf(outfile,"\n");
	    if (i < _num_aggregates)
		prev_edf_x_size = entry->pkt_count;

	    prev_count = i;
	}
	edf_y_val += step;
	i++;

    } while (i <= _num_aggregates);

    delete[] permutation;

    if (fclose(outfile)) {
	click_chatter("error closing file!");
    }

}

static int sorter(const void *av, const void *bv) {
    unsigned a = *((const unsigned *)av);
    unsigned b = *((const unsigned *)bv);
    return a-b;
}

void
CalculateVariance::print_all_aggregates()
{

    FILE *outfile = fopen(_outfilename.cc(), "w");

    if (!outfile) {
        click_chatter("%s: %s", _outfilename.cc(), strerror(errno));
	return;
    }

    fprintf(outfile,"#total pkts %d\n",_total_pkts);
    if (_use_hash) {
	unsigned *permutation = new unsigned[_hashed_counters.size()];
	int i=0;
	for (counter_table::Iterator iter = _hashed_counters.first(); iter; iter++) {
	    permutation[i] = iter.key();
	    CounterEntry ent = iter.value();
	    i++;
	}
	assert(i < _num_aggregates);
	qsort(permutation,i, sizeof(unsigned), &sorter);

	CalculateVariance::CounterEntry *entry;
	for (int j=0;j<i;j++) {
	    entry = _hashed_counters.findp(permutation[j]);
	    fprintf(outfile,"%d\t%d\n",  permutation[j], entry->pkt_count);
	}
	
	delete[] permutation;
    }else{
	for (int j=0;j<_num_aggregates;j++) {
	    if (_counters[j].pkt_count>0) 
		fprintf(outfile,"%d\t%d\n",j,_counters[j].pkt_count);
	}
    }

    if (fclose(outfile)) {
	click_chatter("error closing file!");
    }
}

void
CalculateVariance::print_top_aggregates()
{
    FILE *outfile = fopen(_outfilename.cc(), "w");
    if (!outfile) {
        click_chatter("%s: %s", _outfilename.cc(), strerror(errno));
	return;
    }

    for (int i=0;i<top_agg_index;i++) {
	fprintf(outfile,"%d.%d\t%.3f\t%d\t%d\n", top_aggregates[i]._which_interval.tv_sec, top_aggregates[i]._which_interval.tv_usec, top_aggregates[i]._percentage, top_aggregates[i]._which_agg, top_aggregates[i]._num_pkts);
    }

    if (fclose(outfile)) {
	click_chatter("error closing file!");
    }
   
}

static String
calculatevariance_read_variance_handler(Element *e, void *thunk)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    int row = (int)thunk;
    return "\n";
    //return String(cv->variance(row)) + "\n";
}

static String
calculatevariance_print_all_variance_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_all_variance();
    return String("");
}

static String
calculatevariance_print_edf_function_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_edf_function();
    return String("");
}

static String
calculatevariance_print_top_aggregates_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_top_aggregates();
    return String("");
}

static String
calculatevariance_print_all_aggregates_handler(Element *e, void *)
{
    CalculateVariance *cv = (CalculateVariance *)e;
    cv->print_all_aggregates();
    return String("");
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
    add_read_handler("printtopaggregates",calculatevariance_print_top_aggregates_handler,0);
    add_read_handler("printallaggregates",calculatevariance_print_all_aggregates_handler,0);
    add_write_handler("reset",calculatevariance_reset_write_handler,0);
}

EXPORT_ELEMENT(CalculateVariance)

#include <click/vector.cc>
#include <click/bighashmap.cc>
#if EXPLICIT_TEMPLATE_INSTANCES
template class BigHashMap<int, CalculateVariance::CounterEntry>
#endif
