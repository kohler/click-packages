// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>
#include "calculatecapacity.hh"
#include <click/error.hh>
#include <click/hashtable.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>
#include "elements/analysis/aggregateipflows.hh"
#include "elements/analysis/toipsumdump.hh"
#include <math.h>
CLICK_DECLS

CalculateCapacity::StreamInfo::StreamInfo()
    : have_init_seq(false),
      init_seq(0),
      pkt_head(0), pkt_tail(0),
      pkt_cnt(0), mss(0), rmss(0),
      intervals(0), hist(0),
      cutoff(0), valid(0)
{
}

CalculateCapacity::StreamInfo::~StreamInfo()
{
    if(intervals) delete[] intervals;
    if(hist) delete[] hist;
    if(cutoff) delete[] cutoff;
    if(valid) delete[] valid;
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
    if (p->timestamp_anno())
	_init_time = p->timestamp_anno() - Timestamp::epsilon();

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
    fprintf(f, "  <stream dir='%d' beginseq='%u' mss='%u' mssr='%u'>\n",
	    direction, init_seq, mss, rmss);
    for(Vector<struct Peak *>::const_iterator iter = peaks.begin();
	iter != peaks.end(); iter++){
	p = *iter;
	fprintf(f, "   <peak center='%lf' area='%d' left='%lf' right='%lf' ",
		p->center, p->area, p->left, p->right);
	fprintf(f, "acknone='%lf' ackone='%lf' acktwo='%lf' ackmore='%lf'",
		p->acknone, p->ackone, p->acktwo, p->ackmore);
	fprintf(f, " />\n");
    }

    fprintf(f,"    <interarrival>\n");
    for(unsigned int i=0; i < pkt_cnt; i++){
	fprintf(f, "%d " PRITIMESTAMP " %d " PRITIMESTAMP "\n", intervals[i].size,
		intervals[i].interval.sec(),
		intervals[i].interval.subsec(),
		intervals[i].newack,
		intervals[i].time.sec(),
		intervals[i].time.subsec());
    }
    fprintf(f,"    </interarrival>\n");
    fprintf(f, " </stream>\n");
}

static int compare(const void *a, const void *b, void *){
    struct CalculateCapacity::StreamInfo::IntervalStream *ac;
    struct CalculateCapacity::StreamInfo::IntervalStream *bc;
    double iratea, irateb;

    ac = (CalculateCapacity::StreamInfo::IntervalStream *)a;
    bc = (CalculateCapacity::StreamInfo::IntervalStream *)b;

    iratea = ac->interval.doubleval() / ((ac->size)*8.0);
    irateb = bc->interval.doubleval() / ((bc->size)*8.0);

    if(ac->interval < bc->interval) return -1;
    if(ac->interval == bc->interval) return -1;
    return 1;

    if(iratea < irateb) return -1;
    if(iratea == irateb) return 0;
    return 1;
}

static int compare_time(const void *a, const void *b, void *){
    struct CalculateCapacity::StreamInfo::IntervalStream *ac;
    struct CalculateCapacity::StreamInfo::IntervalStream *bc;

    ac = (CalculateCapacity::StreamInfo::IntervalStream *)a;
    bc = (CalculateCapacity::StreamInfo::IntervalStream *)b;

    if(ac->time < bc->time) return -1;
    if(ac->time == bc->time) return 0;
    return 1;
}


void
CalculateCapacity::StreamInfo::findpeaks()
{
    struct Peak *peak;
    double *logs;
    double *slopes;
    uint32_t j;
    uint32_t n;
    uint32_t slopelen;
    uint32_t lefti=0;
    uint32_t righti;

    logs = new double[pkt_cnt];
    slopes = new double[pkt_cnt];

    //printf("pktcnt %d\n", pkt_cnt);
    for(j = 0, n = 0; j < pkt_cnt; j++){
	struct IntervalStream *i = intervals + j;
	Timestamp *t = &(i->interval);
	if (!*t)
	    continue;
	if(i->size < 500 && i->newack < 500){
	    continue;
	}
	logs[n] = log(t->doubleval());
	n++;
	//printf("%d %f\n", j - pkt_cnt + n, logs[j - pkt_cnt + n]);
    }

    slopelen = (uint32_t) (0.01 * n);
    if(slopelen < 1) {
	slopelen = 1;
    }
    for(j = 0 ; j < n ; j++){
	uint32_t imin, imax;
	imin = j < slopelen ? 0 : j - slopelen;
	imax = j + slopelen >= n-1 ? n-1 : j + slopelen;
	slopes[j] = (logs[imax] - logs[imin]) / (imax - imin) ;
    }

    double expectedslope = (logs[n-1] - logs[0]) / n;
    //printf("expected islope: %f\n", expectedslope);
    double peakstart = 0.2 * expectedslope;
    double peakend = 0.5 * expectedslope;
    bool inpeak = false;

    peak = new Peak;

    for(j = 0; j < n; j++){
	if(inpeak){
	    if(slopes[j] < peakend){
		peak->area++;
	    } else {
		//end of peak here
		righti = j-1;
		peak->right = exp(logs[righti]);;
		uint32_t cint = (righti + lefti)/2;
		peak->center = exp(logs[cint]);
		if(peak->area > 2){
		    peaks.push_back(peak);
		} else {
		    delete peak;
		}
		inpeak = false;
		peak = new Peak;
	    }
	} else {
	    if(slopes[j] < peakstart){
		uint32_t k=j;
		//new peak here
		inpeak = true;
		peak->area = 1;
		while(k > 0 && slopes[k-1] < peakend)
		    k--;
		lefti = k;
		peak->left = exp(logs[lefti]);
		peak->area += j-k;
	    } else {
		//nothing
	    }

	}
    }
    if(inpeak){
	//end peak here
	righti = n-1;
	peak->right = exp(logs[righti]);;
	uint32_t cint = (righti + lefti)/2;
	peak->center = exp(logs[cint]);
	if(peak->area > 2){
	    peaks.push_back(peak);
	} else {
	    delete peak;
	}
    } else {
	delete peak;
    }

    delete[] logs;
    delete[] slopes;

    //what is the ack size for these peaks?
    for(Vector<struct Peak *>::const_iterator iter = peaks.begin();
	iter != peaks.end(); iter++){
	struct Peak *p = *iter;
	uint32_t cnt = 0;
	uint32_t none = 0;
	uint32_t one = 0;
	uint32_t two = 0;
	uint32_t more = 0;
	for(uint32_t j = 0 ; j < pkt_cnt; j++){
	    struct IntervalStream *i = intervals + j;
	    Timestamp *t = &(i->interval);
	    double ft = t->doubleval();
	    if(cnt == 0 && ft < p->left)
		continue;
	    if(cnt > 0 && ft > p->right)
		break;
	    if(i->size > rmss / 2 || i->newack < 0.5 * rmss){
		none++;
	    } else if (i->newack < 1.5 * rmss){
		one++;
	    } else if (i->newack < 2.5 * rmss){
		two++;
	    } else {
		more++;
	    }
	    cnt++;
	}
	if(cnt == 0){
	    printf("empty peak %d\n", peak->area);
	}
	if(cnt != p->area){
	    //printf("missing %d peak packets %d %d\n", p->area - cnt, p->area, cnt);
	}

	p->acknone = none / (double)cnt;
	p->ackone = one / (double)cnt;
	p->acktwo = two / (double)cnt;
	p->ackmore = more / (double)cnt;
    }


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
	      intervals[j].interval.doubleval() < curr){
	    if(mss == intervals[j].size ||
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
// 	printf("  " PRITIMESTAMP "\n", intervals[j].interval.sec(),
// 	       intervals[j].interval.subsec());
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
    intervals = new IntervalStream[pkt_cnt];

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
// 	printf("%d %d " PRITIMESTAMP " %d\n", pkt_cnt, intervals[i].size+40,
// 	       intervals[i].interval.sec(),
// 	       intervals[i].interval.subsec(),
// 	       intervals[i].newack);
//     }


}

void
CalculateCapacity::StreamInfo::fill_shortrate()
{
    uint32_t i,j;
    uint32_t ackbytes=0;
    uint32_t databytes=0;
    double time_windowsize = 3.0;

    datarate = 0;
    ackrate = 0;
    ackstart = Timestamp();
    datastart = Timestamp();

    click_qsort(intervals, pkt_cnt, sizeof(struct IntervalStream),
    		&compare_time);

    for(i=0;i<pkt_cnt;i++){
	ackbytes = intervals[i].newack;
	databytes = intervals[i].size;
	Timestamp start = intervals[i].time;
	for(j=i+1 ; j<pkt_cnt ; j++){
	    if((intervals[j].time - start).doubleval() < time_windowsize){
		ackbytes += intervals[j].newack;
		databytes += intervals[j].size;
	    } else {
		j--;
		break;
	    }

	    assert(intervals[j].time >= start);
	}
	if(j >= pkt_cnt-1)
	    continue;
	//printf("j-1: %d\n", j-i);
	//must be larger than any single flight
	double timetmp = j - i > 20 ?
	    (intervals[j].time - start).doubleval() : time_windowsize;
	double tmp = ackbytes / timetmp;
	if(tmp > ackrate){
	    ackrate = tmp;
	    ackstart = intervals[j].time;//start;
	    abytes = ackbytes;
	}
	tmp = databytes / timetmp;
	if(tmp > datarate){
	    datarate = tmp;
	    datastart = intervals[j].time;//start;
	    dbytes = databytes;
	}

// 	if(ackbytes > 0){
// 	    printf("ack bytes: %d\n", ackbytes);
// 	}

	    //printf("data bytes: %d\nack bytes: %d\n", databytes, ackbytes);
    }

    datarate *= 8;
    ackrate *= 8;

    click_qsort(intervals, pkt_cnt, sizeof(struct IntervalStream),
    		&compare);


}


void
CalculateCapacity::ConnInfo::kill(CalculateCapacity *cf)
{
    if (FILE *f = cf->traceinfo_file()) {
	Timestamp end_time = (_stream[0].pkt_tail ? _stream[0].pkt_tail->timestamp : _init_time);
	if (_stream[1].pkt_tail && _stream[1].pkt_tail->timestamp > end_time)
	    end_time = _stream[1].pkt_tail->timestamp;

	fprintf(f, "<flow aggregate='%u' src='%s' sport='%d' dst='%s' dport='%d' begin='" PRITIMESTAMP "' duration='" PRITIMESTAMP "'",
		_aggregate, _flowid.saddr().unparse().c_str(), ntohs(_flowid.sport()),
		_flowid.daddr().unparse().c_str(), ntohs(_flowid.dport()),
		_init_time.sec(), _init_time.subsec(),
		end_time.sec(), end_time.subsec());
	if (_filepos)
	    fprintf(f, " filepos='%s'", String(_filepos).c_str());
	fprintf(f, ">\n");

	_stream[0].fill_intervals();
	_stream[0].fill_shortrate();
	_stream[0].histogram();
	_stream[0].findpeaks();

	_stream[1].fill_intervals();
	_stream[1].fill_shortrate();
	_stream[1].histogram();
	_stream[1].findpeaks();

	uint32_t bigger = 0;
	double drate = 0;
	double arate = 0;

	if(_stream[1].pkt_tail &&
	   _stream[0].pkt_tail->last_seq < _stream[1].pkt_tail->last_seq){
	    bigger = 1;
	}

	drate = _stream[bigger].datarate;
	arate = _stream[!bigger].ackrate;
	Timestamp atime = _stream[!bigger].ackstart;
	Timestamp dtime = _stream[bigger].datastart;
	uint32_t abytes = _stream[!bigger].abytes;
	uint32_t dbytes = _stream[bigger].dbytes;

// 	if((drate == 0 || arate == 0) || _aggregate == 1821){
// 	    printf("rate zero: %u\n %lf %lf\n %lf %lf\n",
// 		   _aggregate,
// 		   _stream[0].datarate,
// 		   _stream[0].ackrate,
// 		   _stream[1].datarate,
// 		   _stream[1].ackrate
// 		   );
// 	}

	fprintf(f, "  <rate data='%lf' ack='%lf' dir='%u' "
		"dtime='" PRITIMESTAMP "' atime='" PRITIMESTAMP "' db='%d' ab='%d' />\n",
		drate, arate, bigger, dtime.sec(), dtime.subsec(),
		atime.sec(), atime.subsec(), dbytes, abytes);


	_stream[0].write_xml(f);
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
	stream.mss = stream.mss > size ? stream.mss : size;
	ack_stream.rmss = stream.mss;

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
    : _traceinfo_file(0), _filepos_h(0),
      _free_pkt(0), _packet_source(0)
{
}

CalculateCapacity::~CalculateCapacity()
{
    for (int i = 0; i < _pkt_bank.size(); i++)
	delete[] _pkt_bank[i];
    delete _filepos_h;
}

int
CalculateCapacity::configure(Vector<String> &conf, ErrorHandler *errh)
{
    AggregateIPFlows *af = 0;
    if (Args(conf, this, errh)
	.read_p("TRACEINFO", FilenameArg(), _traceinfo_filename)
	.read("SOURCE", _packet_source)
	.read("NOTIFIER", ElementCastArg("AggregateIPFlows"), af)
	.complete() < 0)
        return -1;

    if (af)
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
    else if (!(_traceinfo_file = fopen(_traceinfo_filename.c_str(), "w")))
	return errh->error("%s: %s", _traceinfo_filename.c_str(), strerror(errno));
    if (_traceinfo_file) {
	fprintf(_traceinfo_file, "<?xml version='1.0' standalone='yes'?>\n\
<trace");
	if (String s = HandlerCall::call_read(_packet_source, "filename").trim_space())
	    fprintf(_traceinfo_file, " file='%s'", s.c_str());
	fprintf(_traceinfo_file, ">\n");
	HandlerCall::reset_read(_filepos_h, _packet_source, "packet_filepos");
    }

    return 0;
}

void
CalculateCapacity::cleanup(CleanupStage)
{
    for (ConnMap::iterator iter = _conn_map.begin(); iter.live(); iter++) {
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
	ConnInfo *loss = _conn_map.get(aggregate);
	if (!loss) {
	    if ((loss = new ConnInfo(p, _filepos_h)))
		_conn_map.set(aggregate, loss);
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
	if (ConnInfo *tmploss = _conn_map.get(aggregate)) {
	    _conn_map.erase(aggregate);
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
	for (ConnMap::iterator i = cf->_conn_map.begin(); i.live(); i++)
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
CLICK_ENDDECLS
