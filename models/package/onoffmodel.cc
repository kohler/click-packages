#include <click/config.h>
#include "onoffmodel.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <packet_anno.hh>
#include <click/click_tcp.h>
#include <click/router.hh>


OnOffModel::OnOffModel()
    : Element(1,1)
{
    MOD_INC_USE_COUNT;

    _start_time.tv_sec = 0;
    _start_time.tv_usec = 0;

    _end_time.tv_sec = 0;
    _end_time.tv_usec = 0;
}

OnOffModel::~OnOffModel()
{
    MOD_DEC_USE_COUNT;
}

int
OnOffModel::configure(Vector<String> &conf, ErrorHandler *errh)
{

    if (cp_va_parse(conf, this, errh,
		cpTimeval, "max. silence interval allowed in ON period (struct timeval)", &_max_silence_int,
		cpTimeval,"stop after xxx seconds", &_effective_duration,
		    0) < 0) 
	return -1;
    return 0;
}


Packet *
OnOffModel::simple_action(Packet *p)
{

    IPAddress useraddr;

    if (_start_time.tv_sec == 0) {
	_start_time = p->timestamp_anno();
	timeradd(&_start_time, &_effective_duration, &_stop_time); 
    }

    if (timercmp(&p->timestamp_anno(),&_stop_time,>)) {
	router()->please_stop_driver();
    }

    _end_time = p->timestamp_anno();

    //currently, this ON OFF Model only access web traffic 
    //and it assumes the non-80 port corresponds to a user
    const click_ip *iph = p->ip_header();
    const click_tcp *tcph = p->tcp_header();
    unsigned short sport = ntohs(tcph->th_sport);
    unsigned short dport = ntohs(tcph->th_dport);
    
    if (sport == 80) {
	useraddr = IPAddress(iph->ip_dst);
    }else{
	if (dport!=80) {
	    printf("source port %d destination port %d\n",sport,dport);
	}
	useraddr = IPAddress(iph->ip_src);
    }

    OnOffConnCounter *c = _hashed_counters.findp(useraddr);
    if (!c) {
	OnOffConnCounter newc = OnOffConnCounter(p->timestamp_anno(),1,p->length());
	_hashed_counters.insert(useraddr,newc);
    }else {
	c->total_user_bytes += (double)p->length();
	struct timeval timeexpire;	
	timeradd( &c->end_time, &_max_silence_int, &timeexpire);
	if (timercmp(&timeexpire, &p->timestamp_anno(), >)) {
	    c->pkt_counts++;
	    c->byte_counts += p->length();
	    c->end_time = p->timestamp_anno();
	}else{
	    //collect the previos ON period statistics
	    struct timeval diff;
	    timersub(&c->end_time,&c->start_time, &diff);
	    double duration = diff.tv_sec + 0.000001 * diff.tv_usec;
	    double on_throughput = c->byte_counts/duration;
	  
	    if (duration > 2) {
		c->total_on_duration += duration;
		c->total_on_throughput += on_throughput;
		if (on_throughput>c->max_on_throughput) {
		    c->max_on_throughput  = on_throughput;
		}
		c->total_on_transfers++;
		c->total_on_throughput_sqr += on_throughput*on_throughput;
	    }

	    //collect the previous OFF period statistics
	    timersub(&p->timestamp_anno(), &c->end_time, &diff);
	    duration = diff.tv_sec + 0.000001 * diff.tv_usec;
	    c->total_off_times++;
	    c->total_off_duration += duration;
	    c->total_off_duration_sqr += duration*duration;

	    //clear the per-transfer state
	    c->start_time = p->timestamp_anno();
	    c->end_time = p->timestamp_anno();
	    c->pkt_counts = 1;
	    c->byte_counts = p->length();
	}
    }

    return p;

}

int
OnOffModel::write_file(String where, ErrorHandler *errh) const 
{
    FILE *f;
    if (where == "-") 
	f = stdout;
    else
	f = fopen(where.cc(),"w");

    if (!f)
	return errh->error("%s: %s", where.cc(),strerror(errno));

    double avg_on_throughput;
    double var_on_throughput;
    double avg_off_duration;
    double var_off_duration;

    struct timeval diff;
    timersub(&_end_time, &_start_time, &diff);
    double total_trace_time = diff.tv_sec + 0.000001 * diff.tv_usec;

    for (onoff_countertable::Iterator iter = _hashed_counters.first(); iter; iter++) {

	IPAddress addr = (IPAddress) iter.key();
	OnOffConnCounter c = iter.value();
    
	if ((c.total_on_transfers ==0 ) || (c.total_off_times == 0)) {
	    continue;
	}

	avg_on_throughput = c.total_on_throughput/c.total_on_transfers;
	var_on_throughput = c.total_on_throughput_sqr/c.total_on_transfers - (avg_on_throughput * avg_on_throughput);
	avg_off_duration = c.total_off_duration/c.total_off_times;
	var_off_duration = c.total_off_duration_sqr/c.total_off_times - (avg_off_duration * avg_off_duration);

	fprintf(f,"%s %.2f %.2f %d %.2f %.2f %.2f %.2f %d %.2f %.2f\n", addr.s().cc(), c.total_user_bytes, total_trace_time, c.total_on_transfers, c.total_on_duration,
		avg_on_throughput,var_on_throughput,c.max_on_throughput, c.total_off_times, avg_off_duration, var_off_duration);
    }
}

static int
onoffmodel_write_file_handler(const String &data, Element *e, void *, ErrorHandler *errh)
{
    OnOffModel *m = static_cast<OnOffModel *>(e);
    String fn;
    if (!cp_filename(cp_uncomment(data),&fn))
	return errh->error("agument should be a filename");
    return m->write_file(fn,errh);
    
}

void
OnOffModel::add_handlers()
{
    add_write_handler("write_ascii_file", onoffmodel_write_file_handler, (void *)0);
}

EXPORT_ELEMENT(OnOffModel)

#include <click/vector.cc>
#include <click/bighashmap.cc>
#if EXPLICIT_TEMPLATE_INSTANCES
template class BigHashMap<IPAddress, OnOffModel::OnOffConnCounter>
#endif
