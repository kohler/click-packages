// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>
#include "calculatecapacity.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/straccum.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include "elements/analysis/aggregateipflows.hh"
#include "elements/analysis/toipsumdump.hh"
CLICK_DECLS

static inline struct timeval
operator*(double frac, const struct timeval &tv)
{
    double what = frac * (tv.tv_sec + tv.tv_usec / 1e6);
    int32_t sec = (int32_t)what;
    return make_timeval(sec, (int32_t)((what - sec) * 1e6));
}

CalculateCapacity::StreamInfo::StreamInfo()
    : have_init_seq(false),
      init_seq(0),
      pkt_head(0), pkt_tail(0),
      pkt_cnt(0), max_size(0),
      intervals(0), hist(0),
      cutoff(0), valid(0)
{
}

CalculateCapacity::StreamInfo::~StreamInfo()
{
    if(intervals) delete intervals;
    if(hist) delete hist;
    if(cutoff) delete cutoff;
    if(valid) delete valid;
}



// CONNINFO

CalculateCapacity::ConnInfo::ConnInfo(const Packet *p, const HandlerCall *filepos_call)
    : _aggregate(AGGREGATE_ANNO(p))
{
    assert(_aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header())
	   && p->transport_length() >= (int)sizeof(click_udp));
    _flowid = IPFlowID(p);
    
    // set initial timestamp
    if (timerisset(&p->timestamp_anno()))
	_init_time = p->timestamp_anno() - make_timeval(0, 1);
    else
	timerclear(&_init_time);

    // set file position
    if (filepos_call)
	_filepos = filepos_call->call_read().trim_space();

    // initialize streams
    _stream[0].direction = 0;
    _stream[1].direction = 1;
}



void
CalculateCapacity::StreamInfo::write_xml(FILE *f) const
{
    struct Peak *p;
    fprintf(f, "  <stream dir='%d' beginseq='%u' maxsize='%u'>\n",
	    direction, init_seq, max_size);
    for(Vector<struct Peak *>::const_iterator iter = peaks.begin();
	iter!= peaks.end(); iter++){
	p = *iter;
	fprintf(f, "   <peak center='%lf' index='%d' area='%d' left='%d' right='%d' />\n",
		p->center, p->index, p->area, p->left, p->right);
    }
    
    fprintf(f,"    <interarrival>\n");
    for(unsigned int i=0; i < pkt_cnt; i++){
	fprintf(f, "%d %ld.%06ld %d %ld.%06ld\n", intervals[i].size,
		intervals[i].interval.tv_sec,
		intervals[i].interval.tv_usec,
		intervals[i].newack,
		intervals[i].time.tv_sec,
		intervals[i].time.tv_usec);
    }
    fprintf(f,"    </interarrival>\n");
    fprintf(f, " </stream>\n");
}

static int compare(const void *a, const void *b){
    struct CalculateCapacity::StreamInfo::IntervalStream *ac;
    struct CalculateCapacity::StreamInfo::IntervalStream *bc;
    double iratea, irateb;

    ac = (CalculateCapacity::StreamInfo::IntervalStream *)a;
    bc = (CalculateCapacity::StreamInfo::IntervalStream *)b;
    
    iratea = (ac->interval.tv_sec + ac->interval.tv_usec/1.0e6)
	/ ((ac->size)*8.0);
    irateb = (bc->interval.tv_sec + bc->interval.tv_usec/1.0e6)
	/ ((bc->size)*8.0);

    if(ac->interval < bc->interval) return -1;
    if(ac->interval == bc->interval) return -1;
    return 1;

    if(iratea < irateb) return -1;
    if(iratea == irateb) return 0;
    return 1;
}

void
CalculateCapacity::StreamInfo::findpeaks(uint32_t npeaks)
{
    uint32_t max;
    uint32_t maxi;
    struct Peak *peak;

    while(npeaks > 0){
	
	uint32_t i, prev, area;
	max = 0;
	maxi = histpoints+1;
	uint32_t rightedge, leftedge;
	bool combined = false;

	for(i=1; i < histpoints; i++){
	    if(valid[i] && hist[i] > max && hist[i] > 2){
		max = hist[i];
		maxi = i;
	    }
	}
	
	if(maxi > histpoints){
	    //no new ones
	    break;
	}

	//remove surrounding areas
	valid[maxi] = 0;
	prev = area = max;
	
	rightedge = leftedge = maxi;

	i = maxi + 1;
	while(i < histpoints && valid[i] && hist[i] > 0 && hist[i]-1 < prev){
	    area += hist[i];
	    valid[i]=0;
	    prev = hist[i];
	    i++;
	    rightedge++;
	}

	i = maxi - 1;
	prev = max;
	while(i > 0 && valid[i] && hist[i] > 0 && hist[i]-1 < prev){
	    area += hist[i];
	    valid[i]=0;
	    prev = hist[i];
	    i--;
	    leftedge--;
	}

	//should this be combined with an existing peak or be a new one?
	//should pick the bigger of possible neighbors
	for(Vector<struct Peak *>::const_iterator iter = peaks.begin();
	    iter!=peaks.end(); iter++){
	    struct Peak *p = *iter;
	    if(leftedge - 1 == p->right || leftedge - 2 == p->right){
		p->right = rightedge;
		p->area += area;
		combined = true;
		break;
	    }
	    if(rightedge + 1 == p->left || rightedge + 2 == p->left){
		p->area += area;
		combined = true;
		break;
	    }
	}
	
	if(combined){
	    //printf("combined\n");
	    continue;
	}

	//append to list of peaks
	peak = new Peak;
	peak->area = area;
	peak->center = (cutoff[i] + cutoff[i-1]) / 2;
	peak->index = maxi;
	peak->left = leftedge;
	peak->right = rightedge;
	peaks.push_back(peak);
	
	npeaks--;
    }

    //printf("done adding peaks\n");
    fflush(stdout);

}

void
CalculateCapacity::StreamInfo::histogram()
{
    uint32_t i;
    double stepsize; // in seconds
    double curr; // in seconds
    const double factor=1.009;
    const uint32_t howmany = 1000;
    
    uint32_t j=0;
    uint32_t totcnt=0;
    uint32_t usedcnt=0;

    histpoints = howmany;
    hist = new uint32_t[howmany];
    cutoff = new double[howmany];
    valid = new uint8_t[howmany];

    curr = 1.0e-6;
    stepsize = 1.0e-6;
    
    for(i=0; i < howmany; i++){
	stepsize *= factor;
	curr += stepsize;
	cutoff[i] = curr;
	hist[i] = 0;
	valid[i] = 1;
	
	while(j < pkt_cnt &&
	      (intervals[j].interval.tv_sec +
	       intervals[j].interval.tv_usec * 1.0e-6) < curr){
	    if(max_size == intervals[j].size ||
	       (intervals[j].size < 100 &&
		intervals[j].newack > 500)){
		hist[i]++;
		usedcnt++;
	    }
	    j++;
	    totcnt++;
	}
    }

//     if(totcnt != pkt_cnt){
// 	printf("missing %d packets: %d %d\n", pkt_cnt - totcnt,
// 	       totcnt, pkt_cnt);
// 	printf("  %ld.%06ld\n", intervals[j].interval.tv_sec,
// 	       intervals[j].interval.tv_usec);
// 	printf("  %lf %lf\n", curr, stepsize);
//     }

//    if(usedcnt < totcnt){
//	printf("%d %d %d\n", totcnt, usedcnt, totcnt - usedcnt);
//   }

}

void
CalculateCapacity::StreamInfo::fill_intervals() 
{
    uint32_t i=0;
    Pkt *cp;
    intervals = new IntervalStream[sizeof(struct IntervalStream) * pkt_cnt];
    
    for(cp = pkt_head, i=0; cp != NULL && i < pkt_cnt; i++, cp=cp->next){
	intervals[i].size = cp->last_seq - cp->seq + cp->hsize;
	if(intervals[i].size > 1500){
	    printf("huh?\n%d\n%d\n%d\n",
		   intervals[i].size,
		   cp->last_seq, cp->seq);
	}
	

	if(cp->flags & TH_ACK && cp->prev && cp->prev->flags & TH_ACK &&
	   cp->ack > cp->prev->ack){
	    intervals[i].newack = cp->ack - cp->prev->ack;
	} else{
	    intervals[i].newack = 0;
	}

	//if it appears to be acking more than, oh, say 5 packets then
	//we're probably not seeing all the acks
	intervals[i].newack = intervals[i].newack < 5 * 1500 ?
	    intervals[i].newack : 0;

// 	if(intervals[i].newack > 30000){
// 	    printf("ack? %d\n%d\n%d\n%d\n", i, intervals[i].newack,
// 		   cp->ack, cp->prev->ack);
// 	}

	intervals[i].time = cp->timestamp;

	intervals[i].interval = cp->timestamp -
	    (cp->prev ? cp->prev->timestamp : cp->timestamp);
    }

    if(i < pkt_cnt){
	printf("missing pkts: %d %d\n", pkt_cnt, i);
    }

    click_qsort(intervals, pkt_cnt, sizeof(struct IntervalStream),
    		&compare);

//     for(unsigned int i=0; i < pkt_cnt; i++){
// 	printf("%d %d %ld.%06ld %d\n", pkt_cnt, intervals[i].size+40,
// 	       intervals[i].interval.tv_sec,
// 	       intervals[i].interval.tv_usec,
// 	       intervals[i].newack);
//     }


}

void
CalculateCapacity::ConnInfo::kill(CalculateCapacity *cf)
{
    if (FILE *f = cf->traceinfo_file()) {
	timeval end_time = (_stream[0].pkt_tail ? _stream[0].pkt_tail->timestamp : _init_time);
	if (_stream[1].pkt_tail && _stream[1].pkt_tail->timestamp > end_time)
	    end_time = _stream[1].pkt_tail->timestamp;
	
	fprintf(f, "<flow aggregate='%u' src='%s' sport='%d' dst='%s' dport='%d' begin='%ld.%06ld' duration='%ld.%06ld'",
		_aggregate, _flowid.saddr().s().cc(), ntohs(_flowid.sport()),
		_flowid.daddr().s().cc(), ntohs(_flowid.dport()),
		_init_time.tv_sec, _init_time.tv_usec,
		end_time.tv_sec, end_time.tv_usec);
	if (_filepos)
	    fprintf(f, " filepos='%s'", String(_filepos).cc());
	fprintf(f, ">\n");
	
	_stream[0].fill_intervals();
	_stream[0].histogram();
	_stream[0].findpeaks(12);
	_stream[0].write_xml(f);
	_stream[1].fill_intervals();
	_stream[1].histogram();
	_stream[1].findpeaks(12);
	_stream[1].write_xml(f);
	fprintf(f, "</flow>\n");
    }
    cf->free_pkt_list(_stream[0].pkt_head, _stream[0].pkt_tail);
    cf->free_pkt_list(_stream[1].pkt_head, _stream[1].pkt_tail);
    delete this;
}

CalculateCapacity::Pkt *
CalculateCapacity::ConnInfo::create_pkt(const Packet *p, CalculateCapacity *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && IP_FIRSTFRAG(p->ip_header())
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // set TCP sequence number offsets on first Pkt
    const click_tcp *tcph = p->tcp_header();
    int direction = (PAINT_ANNO(p) & 1);
    StreamInfo &stream = _stream[direction];
    if (!stream.have_init_seq) {
	stream.init_seq = ntohl(tcph->th_seq);
	stream.have_init_seq = true;
    }
    StreamInfo &ack_stream = _stream[!direction];
    if ((tcph->th_flags & TH_ACK) && !ack_stream.have_init_seq) {
	ack_stream.init_seq = ntohl(tcph->th_ack);
	ack_stream.have_init_seq = true;
    }

    // introduce a Pkt
    if (Pkt *np = parent->new_pkt()) {
	const click_ip *iph = p->ip_header();
	uint32_t size;

	// set fields appropriately
	np->seq = ntohl(tcph->th_seq) - stream.init_seq;
	np->last_seq = np->seq + calculate_seqlen(iph, tcph);
	np->ack = ntohl(tcph->th_ack) - ack_stream.init_seq;
	np->timestamp = p->timestamp_anno() - _init_time;
	np->flags = tcph->th_flags;
	np->hsize = 4*(tcph->th_off + iph->ip_hl);

	// hook up to packet list
	np->next = 0;
	np->prev = stream.pkt_tail;
	if (stream.pkt_tail)
	    stream.pkt_tail = stream.pkt_tail->next = np;
	else
	    stream.pkt_head = stream.pkt_tail = np;

	stream.pkt_cnt++;
	//can't use p->length() due to truncated traces
	size = np->hsize + np->last_seq - np->seq;
	stream.max_size = stream.max_size > size ? stream.max_size : size;

	return np;
    } else
	return 0;
}

void
CalculateCapacity::ConnInfo::handle_packet(const Packet *p, CalculateCapacity *parent)
{
    assert(p->ip_header()->ip_p == IP_PROTO_TCP
	   && AGGREGATE_ANNO(p) == _aggregate);
    
    // update timestamp and sequence number offsets at beginning of connection
    //if (Pkt *k = create_pkt(p, parent)) {
	//int direction = (PAINT_ANNO(p) & 1);
	//_stream[direction].categorize(k, this, parent);
	//_stream[direction].update_counters(k, p->tcp_header(), this);
    //}
    create_pkt(p, parent);
}


// CalculateCapacity PROPER

CalculateCapacity::CalculateCapacity()
    : Element(1, 1), _traceinfo_file(0), _filepos_h(0),
      _free_pkt(0), _packet_source(0)
{
    MOD_INC_USE_COUNT;
}

CalculateCapacity::~CalculateCapacity()
{
    MOD_DEC_USE_COUNT;
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
    delete _filepos_h;
}

void
CalculateCapacity::notify_noutputs(int n)
{
    set_noutputs(n <= 1 ? 1 : 2);
}

int 
CalculateCapacity::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Element *af_element = 0;
    if (cp_va_parse(conf, this, errh,
		    cpOptional,
		    cpFilename, "output connection info file", &_traceinfo_filename,
		    cpKeywords,
		    "TRACEINFO", cpFilename, "output connection info file", &_traceinfo_filename,
		    "SOURCE", cpElement, "packet source element", &_packet_source,
                    "NOTIFIER", cpElement,  "AggregateIPFlows element pointer (notifier)", &af_element,
		    0) < 0)
        return -1;
    
    AggregateIPFlows *af = 0;
    if (af_element && !(af = (AggregateIPFlows *)(af_element->cast("AggregateIPFlows"))))
	return errh->error("NOTIFIER must be an AggregateIPFlows element");
    else if (af)
	af->add_listener(this);
    
    return 0;
}

int
CalculateCapacity::initialize(ErrorHandler *errh)
{
    if (!_traceinfo_filename)
	/* nada */;
    else if (_traceinfo_filename == "-")
	_traceinfo_file = stdout;
    else if (!(_traceinfo_file = fopen(_traceinfo_filename.cc(), "w")))
	return errh->error("%s: %s", _traceinfo_filename.cc(), strerror(errno));
    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "<?xml version='1.0' standalone='yes'?>\n\
<trace");
	if (String s = HandlerCall::call_read(_packet_source, "filename").trim_space())
	    fprintf(_traceinfo_file, " file='%s'", s.cc());
	fprintf(_traceinfo_file, ">\n");
	HandlerCall::reset_read(_filepos_h, _packet_source, "packet_filepos");
    }

    return 0;
}

void
CalculateCapacity::cleanup(CleanupStage)
{
    for (ConnMap::iterator iter = _conn_map.begin(); iter; iter++) {
	ConnInfo *losstmp = const_cast<ConnInfo *>(iter.value());
	losstmp->kill(this);
    }
    _conn_map.clear();
    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "</trace>\n");
	fclose(_traceinfo_file);
    }
}

CalculateCapacity::Pkt *
CalculateCapacity::new_pkt()
{
    if (!_free_pkt)
	if (Pkt *pkts = new Pkt[1024]) {
	    _pkt_bank.push_back(pkts);
	    for (int i = 0; i < 1024; i++) {
		pkts[i].next = _free_pkt;
		_free_pkt = &pkts[i];
	    }
	}
    if (!_free_pkt)
	return 0;
    else {
	Pkt *p = _free_pkt;
	_free_pkt = p->next;
	p->next = p->prev = 0;
	return p;
    }
}

Packet *
CalculateCapacity::simple_action(Packet *p)
{
    uint32_t aggregate = AGGREGATE_ANNO(p);
    if (aggregate != 0 && p->ip_header()->ip_p == IP_PROTO_TCP) {
	ConnInfo *loss = _conn_map.find(aggregate);
	if (!loss) {
	    if ((loss = new ConnInfo(p, _filepos_h)))
		_conn_map.insert(aggregate, loss);
	    else {
		click_chatter("out of memory!");
		p->kill();
		return 0;
	    }
	}
	loss->handle_packet(p, this);
	return p;
    } else {
	checked_output_push(1, p);
	return 0;
    }
}

void 
CalculateCapacity::aggregate_notify(uint32_t aggregate, AggregateEvent event, const Packet *)
{
    if (event == DELETE_AGG)
	if (ConnInfo *tmploss = _conn_map.find(aggregate)) {
	    _conn_map.remove(aggregate);
	    tmploss->kill(this);
	}
}


enum { H_CLEAR };

int
CalculateCapacity::write_handler(const String &, Element *e, void *thunk, ErrorHandler *)
{
    CalculateCapacity *cf = static_cast<CalculateCapacity *>(e);
    switch ((intptr_t)thunk) {
      case H_CLEAR:
	for (ConnMap::iterator i = cf->_conn_map.begin(); i; i++)
	    i.value()->kill(cf);
	cf->_conn_map.clear();
	return 0;
      default:
	return -1;
    }
}

void
CalculateCapacity::add_handlers()
{
    add_write_handler("clear", write_handler, (void *)H_CLEAR);
}


ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(CalculateCapacity)
#include <click/bighashmap.cc>
CLICK_ENDDECLS
