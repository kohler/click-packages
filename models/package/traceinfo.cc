#include <config.h>
#include <click/config.h>

#include "traceinfo.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <ctime>

/* this will generate the master-xxx file, together with some general trace info. 
   this is an attempt to clear up the messy calculatevariance.cc file */

TraceInfo::TraceInfo()
    : Element(1,1)
{
    MOD_INC_USE_COUNT;
}

TraceInfo::~TraceInfo()
{
    MOD_DEC_USE_COUNT;
}

int
TraceInfo::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_parse(conf, this, errh,
		    cpFilename, "filename for general info. output",&_generaloutfilename,
		    cpFilename, "filename for master file output",&_masteroutfilename,
		    0) < 0) 
	return -1;
    return 0;
}

void
TraceInfo::reset()
{
   _start_time.tv_sec = 0;
   _start_time.tv_usec = 0;

   _end_time.tv_sec = 0;
   _end_time.tv_usec = 0;
   _total_pkts = 0;
   _total_bytes = 0.0;
}

int
TraceInfo::initialize(ErrorHandler *)
{
    reset();
    return 0;
}

Packet *
TraceInfo::simple_action(Packet *p)
{
    uint32_t dstip;

    const click_ip *iph = p->ip_header();
    IPAddress dstaddr = IPAddress(iph->ip_dst);
    dstip = (uint32_t) ntohl(dstaddr.addr());

    if ((_start_time.tv_sec == 0) && (_start_time.tv_usec == 0)) {
	_start_time = p->timestamp_anno();
    }

    _end_time = p->timestamp_anno();

    unsigned *ent = _hashed_counters.findp(dstip);

    if (!ent) {
	_hashed_counters.insert(dstip,0);
	ent = _hashed_counters.findp(dstip);
    }

    *ent = *ent + 1;

    _total_pkts++;
    _total_bytes += ((double) p->length());
    return p;
}

static int sorter(const void *av, const void *bv) {
    unsigned a = *((const unsigned *)av);
    unsigned b = *((const unsigned *)bv);
    return a-b;
}

void
TraceInfo::print_general_file()
{

    FILE *outfile = fopen(_generaloutfilename.cc(), "w");

    if (!outfile) {
        click_chatter("%s: %s", _generaloutfilename.cc(), strerror(errno));
	return;
    }

    struct timeval duration;
    timersub(&_end_time, &_start_time, &duration);

    fprintf(outfile,"duration: %ld\n",duration.tv_sec);
    fprintf(outfile,"start time: %ld %ld\n",_start_time.tv_sec,_start_time.tv_usec);
    char *s = ctime((time_t *)(&_start_time.tv_sec));
    fprintf(outfile,"start time: %s\n",s);
    fprintf(outfile,"total number of packets: %ld\n",_total_pkts);
    fprintf(outfile,"total number of bytes: %3f\n",_total_bytes);
    fprintf(outfile,"total number of distinct destination ip address: %d\n",_hashed_counters.size());

    if (fclose(outfile)) {
	click_chatter("error closing file!");
    }
}

void
TraceInfo::print_master_file()
{

    FILE *outfile = fopen(_masteroutfilename.cc(), "w");

    if (!outfile) {
        click_chatter("%s: %s", _masteroutfilename.cc(), strerror(errno));
	return;
    } 

    unsigned *permutation = new unsigned[_hashed_counters.size()];
    int i=0;
    for (counter_table::iterator iter = _hashed_counters.begin(); iter; iter++) {
	permutation[i] = (unsigned) iter.key();
	i++;
    }
    qsort(permutation,i, sizeof(unsigned), &sorter);

    unsigned *entry; 
    for (int j=0;j<i;j++) {
	entry = _hashed_counters.findp(permutation[j]);
	fprintf(outfile,"%u\t%d\n",  permutation[j], *entry);
    }

    delete[] permutation;

    if (fclose(outfile)) {
	click_chatter("error closing file!");
    }
}

static String
traceinfo_print_master_file_handler(Element *e, void *)
{
    TraceInfo *t = (TraceInfo *)e;
    t->print_master_file();
    return String("");
}

static String
traceinfo_print_general_file_handler(Element *e, void *)
{
    TraceInfo *t = (TraceInfo *)e;
    t->print_general_file();
    return String("");
}

static int
traceinfo_reset_write_handler (const String &, Element *e, void *, ErrorHandler *)
{
    TraceInfo *t = (TraceInfo *)e;
    t->reset();
    return 0;
}

void
TraceInfo::add_handlers()
{
    add_read_handler("printmaster",traceinfo_print_master_file_handler,0);
    add_read_handler("printgeneral",traceinfo_print_general_file_handler,0);
    add_write_handler("reset",traceinfo_reset_write_handler,0);
}

EXPORT_ELEMENT(TraceInfo)

#include <click/vector.cc>
#include <click/bighashmap.cc>
#if EXPLICIT_TEMPLATE_INSTANCES
template class BigHashMap<unsigned, unsigned>
#endif
