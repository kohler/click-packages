// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <math.h>
#include "aggregatenotifier.hh"
#include "aggregateflows.hh"
#include "toipflowdumps.hh"

/*
=c

CalculateFlows([I<KEYWORDS>])

=s

sets aggregate annotation based on flow

=d

CalculateFlows monitors TCP and UDP flows, setting the aggregate annotation on
every passing packet to a flow number, and the paint annotation to a direction
indication. Non-TCP and UDP packets, second and subsequent fragments, and
short packets are emitted on output 1, or dropped if there is no output 1.

CalculateFlows uses source and destination addresses and source and
destination ports to distinguish flows. Reply packets get the same flow
number, but a different paint annotation. Old flows die after a configurable
timeout, after which new packets with the same addresses and ports get a new
flow number. UDP, active TCP, and completed TCP flows have different timeouts.

Flow numbers are assigned sequentially, starting from 1. Different flows get
different numbers. Paint annotations are set to 0 or 1, depending on whether
packets are on the forward or reverse subflow. (The first packet seen on each
flow gets paint color 0; reply packets get paint color 1.)

Keywords are:

=over 8

=item TCP_TIMEOUT

The timeout for active TCP flows, in seconds. Default is 24 hours.

=item TCP_DONE_TIMEOUT

The timeout for completed TCP flows, in seconds. A completed TCP flow has seen
FIN flags on both subflows. Default is 30 seconds.

=item UDP_TIMEOUT

The timeout for UDP connections, in seconds. Default is 1 minute.

=item REAP

The garbage collection interval. Default is 10 minutes of packet time.

=back

=a

AggregateIP, AggregateCounter */

class CalculateFlows : public Element, public AggregateListener { 
	
	public:

    CalculateFlows();
    ~CalculateFlows();

    const char *class_name() const	{ return "CalculateFlows"; }
    CalculateFlows *clone() const	{ return new CalculateFlows; }

    void notify_noutputs(int);
    const char *processing() const	{ return "a/ah"; }
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
	void print_ack_event(unsigned, int,  timeval, unsigned);
	void print_send_event(unsigned, timeval, unsigned , unsigned);
	void gplotp_ack_event(unsigned, int ,timeval, unsigned);
	void gplotp_send_event(unsigned, timeval, unsigned);
	void aggregate_notify(uint32_t aggregate_ID,
                  AggregateEvent event /* can be NEW_AGG or DELETE_AGG */,
                  const Packet *packet /* null for DELETE_AGG */);
	
	Packet *simple_action(Packet *);
	struct TimeInterval {
		timeval	time;
		uint32_t start_byte;
		uint32_t end_byte;
		TimeInterval():start_byte(0), end_byte(0){ };
	};
	class LossInfo;

    typedef BigHashMap<unsigned, short int> MapS;
    typedef BigHashMap<unsigned, timeval> MapT;
    typedef BigHashMap <unsigned, TimeInterval> MapInterval;
    typedef BigHashMap <unsigned, LossInfo*> MapLoss;
    
  private:
    
    LossInfo *loss;
    String outfilename[2];	
    AggregateFlows *af;
    ToIPFlowDumps *tipfd;
    
    MapLoss loss_map;
    
};

class CalculateFlows::LossInfo {
  private:
    tcp_seq_t _last_seq[2];
    tcp_seq_t _upper_wind_seq[2];
    tcp_seq_t _max_wind_seq[2];
    tcp_seq_t _last_ack[2];
    tcp_seq_t _max_seq[2];
    unsigned  _total_bytes[2];
    unsigned  _bytes_lost[2];
    unsigned  _packets_lost[2];
    unsigned  _packets[2];
    unsigned  _loss_events[2];
    unsigned  _p_loss_events[2];
		   
  public:	
    FILE *outfile[5]; // 0,1 for Events Output and 2,3 for statistics and 4 for info files.
    FILE *outfileg[10]; 
    String outfilename[2];	// Event output files using Jitu format 
    String outfilenameg[10]; // 0,1 for Pure acks , 2,3 for xmts , 4,5 for loss Events 
    // 6,7 for Possible loss Events, 8,9 for Data Acks
		
    String outputdir;
    unsigned agganno;
    short int  gnuplot;
    short int  eventfiles;
    short int  has_syn[2];
    short int  has_fin[2];
    MapT time_by_firstseq[2];
    MapT time_by_lastseq[2];
    MapInterval inter_by_time[2];
    MapS acks[2];
    MapS rexmt[2];
    tcp_seq_t  init_seq[2];
    timeval init_time;
    double prev_diff[2];
    short int doubling[2];
    short int prev_doubling[2];
    short int outoforder_pckt;
    unsigned max_ack[2];
    
    
    void init() { 
	gnuplot = 0;
	eventfiles = 0;
	agganno = 0;
	init_time.tv_usec = 0;
	init_time.tv_sec = 0;
	outoforder_pckt = 0;
	
	has_syn[0] = 0;
	has_fin[0] = 0;
	init_seq[0] = 0;
	prev_diff[0] = 0;
	doubling[0] = -1;
	prev_doubling[0] = 0;
	max_ack[0] = 0;
	_upper_wind_seq[0] = 0;
	_max_wind_seq[0] = 0;
	_last_seq[0] = 0;
	_last_ack[0] = 0;
	_max_seq[0] = 0;
	_total_bytes[0] = 0;
	_bytes_lost[0] = 0;
	_packets_lost[0] = 0;
	_packets[0] = 0;
	_loss_events[0] = 0;
	_p_loss_events[0] = 0;
	
	has_syn[1] = 0;
	has_fin[1] = 0;
	init_seq[1] = 0;
	prev_diff[1]=0;
	doubling[1] = -1;
	prev_doubling[1] = 0;
	max_ack[1] = 0;
	_upper_wind_seq[1] = 0;
	_max_wind_seq[1] = 0;
	_last_seq[1] = 0;
	_last_ack[1] = 0;
	_max_seq[1] = 0;
	_total_bytes[1] = 0;
	_bytes_lost[1] = 0;
	_packets_lost[1] = 0;
	_packets[1] = 0;
	_loss_events[1] = 0;
	_p_loss_events[1] = 0;
    }
    LossInfo() { //Void constructor needed for Bighashmap structure
	init();
    }

    LossInfo(String *outfilename, uint32_t aggp, short int gnuplotp, short int eventfilesp) { //regular constructor
	init();
	LossInfoInit(outfilename, aggp, gnuplotp, eventfilesp);
    }
    void LossInfoInit(String *outfilenamep, uint32_t aggp, short int gnuplotp, short int eventfilesp) { 
	String outfilenametmp;
	String *strtmp = new String (aggp);
	gnuplot = gnuplotp;
	eventfiles = eventfilesp;
	agganno = aggp;
	outputdir = "./flown"+ *strtmp;
	system(" mkdir -p ./"+outputdir);
	if (eventfiles){	
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/" + outfilenamep[i];
		outfilename[i] = outfilenametmp;
		outfile[i] = fopen(outfilenametmp.cc(), "w");
	    			//printf ("%s:%d\n",outfilenametmp.cc(),aggp);
		if (!outfile[i]){
		    click_chatter("%s: %s", outfilename[i].cc(), strerror(errno));
		    return;
		}
	    }
	} else {
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/"+ outfilenamep[i];
		outfilename[i] = outfilenametmp;
	    }
	}
	if (gnuplot){  // check if gnuplot output is requested.
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/" + outfilenamep[i];
		outfilenametmp.append("_acks.gp",8);
		outfilenameg[i] = outfilenametmp;
		outfileg[i] = fopen(outfilenametmp.cc(), "w");
		if (!outfileg[i]){
		    click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
		    return;
		}
	    }
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/" + outfilenamep[i];
		outfilenametmp.append("_xmts.gp",8);
		outfilenameg[i+2] = outfilenametmp;
		outfileg[i+2] = fopen(outfilenametmp.cc(), "w");
		if (!outfileg[i+2]){
		    click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
		    return;
		}
	    }
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/"+ outfilenamep[i];
		outfilenametmp.append("_levt.gp",8);
		outfilenameg[i+4] = outfilenametmp;
		outfileg[i+4] = fopen(outfilenametmp.cc(), "w");
		if (!outfileg[i+4]){
		    click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
		    return;
		}
	    }
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/" + outfilenamep[i];
		outfilenametmp.append("_plevt.gp",9);
		outfilenameg[i+6] = outfilenametmp;
		outfileg[i+6] = fopen(outfilenametmp.cc(), "w");
		if (!outfileg[i+6]){
		    click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
		    return;
		}
	    }
	    for (int i = 0 ; i < 2 ; i++){
		outfilenametmp = outputdir + "/" + outfilenamep[i];
		outfilenametmp.append("_dacks.gp",9);
		outfilenameg[i+8] = outfilenametmp;
		outfileg[i+8] = fopen(outfilenametmp.cc(), "w");
		if (!outfileg[i+8]){
		    click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
		    return;
		}
	    }				
	    
	}
	if (eventfiles){
	    for (int i = 0 ; i < 2 ; i++){
		if (fclose(outfile[i])){ 
		    click_chatter("error closing file!");
		}
	    }
	}
	if (gnuplot){  // check if gnuplot output is requested.
	    for (int i = 0 ; i < 10 ; i++){
		if (fclose(outfileg[i])){ 
		    click_chatter("error closing file!");
		}
	    }			
	}		  
    }
    
    ~LossInfo(){
	print_stats();
	
	/*	if (gnuplot){  // check if gnuplot output is requested.
		char tempstr[32];
		for (int i = 0 ; i < 2 ; i++){
		sprintf(tempstr,"./crplots.sh %s",outfilename[i].cc());
		//			printf("./crplots.sh %s",outfilename[i].cc());
		system(tempstr);
		}
		}*/
    }
    
    void print_stats() {
	String outfilenametmp,strtmp;
	for (int i = 0 ; i < 2 ; i++){
	    outfilenametmp = outfilename[i];
	    outfilenametmp.append(".stats",6);
				//printf("%s",outfilenametmp.cc());
	    outfile[i+2] = fopen(outfilenametmp.cc(), "w");
	    if (!outfile[i+2]){
		click_chatter("%s: %s", outfilenametmp.cc(), strerror(errno));
		return;
	    }
	    strtmp = i ? "B->A" : "A->B";
	    fprintf(outfile[i+2], "Flow %d direction from %s \n",agganno,strtmp.cc());
	    fprintf(outfile[i+2], "Total Bytes = [%u]      ", total_bytes(i));
	    fprintf(outfile[i+2], "Total Bytes Lost = [%u]\n",bytes_lost(i));
	    fprintf(outfile[i+2], "Total Packets = [%u]  ",packets(i));
	    fprintf(outfile[i+2], "Total Packets Lost = [%u]\n",packets_lost(i));
	    fprintf(outfile[i+2], "Total Loss Events = [%u]\n",loss_events(i));
	    fprintf(outfile[i+2], "Total Possible Loss Events = [%u]\n",ploss_events(i));
	    fprintf(outfile[i+2], "I saw the start(SYN):[%d], I saw the end(FIN):[%d]",
		    has_syn[i],
		    has_fin[i]);
	    if (fclose(outfile[i+2])){ 
		click_chatter("error closing file!");
	    }
	}
    }


    
    struct timeval Search_seq_interval(tcp_seq_t start_seq, tcp_seq_t end_seq, unsigned paint);
    
    static double timesub (timeval end_time , timeval start_time){
	return ((end_time.tv_sec-start_time.tv_sec) + 0.000001 *(end_time.tv_usec-start_time.tv_usec));
    }
    static double timeadd (timeval end_time , timeval start_time){
	return ((end_time.tv_sec+start_time.tv_sec) + 0.000001 *(end_time.tv_usec+start_time.tv_usec));
    }
    
    void calculate_loss_events(tcp_seq_t seq, unsigned seqlen, const timeval &time, unsigned paint);

    void calculate_loss_events2(tcp_seq_t seq, unsigned seqlen, const timeval &time, unsigned paint, ToIPFlowDumps *tipfdp);

    void calculate_loss(tcp_seq_t seq, unsigned block_size, unsigned paint);
    
    void set_last_seq(tcp_seq_t seq, unsigned paint) {
	assert(paint < 2);
	_last_seq[paint] = seq;
    }
    void set_last_ack(tcp_seq_t ack, unsigned paint) {
	assert(paint < 2);
	_last_ack[paint] = ack;
    }
    void set_total_bytes(unsigned bytes, unsigned paint){
	assert(paint < 2);
	_total_bytes[paint] = bytes;
    }
    void set_packets(unsigned packets, unsigned paint) {
	assert(paint < 2);
	_packets[paint] = packets;
    }
    void inc_packets(unsigned paint) {
	assert(paint < 2);
	_packets[paint]++;
    }
    
    tcp_seq_t last_seq(unsigned paint) const {
	assert(paint < 2);
	return _last_seq[paint];
    }
    tcp_seq_t last_ack(unsigned paint) const {
	assert(paint < 2);
	return _last_seq[paint];
    }
    unsigned total_bytes(unsigned paint) const {
	assert(paint < 2);
	return  _total_bytes[paint];
    }
    unsigned packets(unsigned paint) const {
	assert(paint < 2);
	return _packets[paint];
    }
    unsigned bytes_lost(unsigned paint) const {
	assert(paint < 2);
	return _bytes_lost[paint];
    }
    unsigned loss_events(unsigned paint) const {
	assert(paint < 2);
	return _loss_events[paint];
    }
    unsigned ploss_events(unsigned paint) const {
	assert(paint < 2);
	return _p_loss_events[paint];
    }
    unsigned packets_lost(unsigned paint) const {
	assert(paint < 2);
	return _packets_lost[paint];
    }

};

#endif
