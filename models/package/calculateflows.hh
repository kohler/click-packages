// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/integerid.hh>
#include <click/bighashmap.hh>
#include <math.h>
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

class CalculateFlows : public Element { public:

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
	Packet *simple_action(Packet *);
	struct TimeInterval {
		timeval	time;
		uint32_t start_byte;
		uint32_t end_byte;
		TimeInterval():start_byte(0), end_byte(0){ };
	};
	typedef BigHashMap<unsigned, short int> MapS;
	typedef BigHashMap<unsigned, timeval> MapT;
	typedef BigHashMap <unsigned, TimeInterval> MapInterval;
	class LossInfo;
		LossInfo *loss;
	String outfilename[2];	
	
	class LossInfo {

	private:	
		unsigned  _last_seq[2];
		unsigned  _upper_wind_seq[2];
		unsigned  _lower_wind_seq[2];
		unsigned  _last_ack[2];
		unsigned  _max_seq[2];
		unsigned  _total_bytes[2];
		unsigned  _bytes_lost[2];
		unsigned  _packets_lost[2];
		unsigned  _packets[2];
		unsigned  _loss_events[2];
		   
	public:	
		FILE *outfile[2];
		MapT time_by_firstseq[2];
		MapT time_by_lastseq[2];
		MapInterval inter_by_time[2];
		MapS acks[2];
		MapS rexmt[2];
		unsigned  rel_seq[2];
		double prev_diff[2];
		short int doubling[2];
		short int prev_doubling[2];
		
		void init() { 
			prev_diff[0] = 0;
			doubling[0] = -1;
			prev_doubling[0] = 0;
			_upper_wind_seq[0] = 0;
			_lower_wind_seq[0] = 0;
			_last_seq[0] = 0;
			_last_ack[0] = 0;
			_max_seq[0] = 0;
			_total_bytes[0] = 0;
			_bytes_lost[0] = 0;
			_packets_lost[0] = 0;
			_packets[0] = 0;
			_loss_events[0] = 0;
			
			
			prev_diff[1]=0;
			doubling[1] = -1;
			prev_doubling[1] = 0;
			_upper_wind_seq[1] = 0;
			_lower_wind_seq[1] = 0;
			_last_seq[1] = 0;
			_last_ack[1] = 0;
			_max_seq[1] = 0;
			_total_bytes[1] = 0;
			_bytes_lost[1] = 0;
			_packets_lost[1] = 0;
			_packets[1] = 0;
			_loss_events[1] = 0;
		};
			
		LossInfo(String *outfilename) { 
			init();
			for (int i = 0 ; i < 2 ; i++){
				//printf("%s",outfilename[i].cc());
				outfile[i] = fopen(outfilename[i].cc(), "w");
	    		if (!outfile[i]){
    	    		click_chatter("%s: %s", outfilename[i].cc(), strerror(errno));
	        		return;
				}
			}
    	};
		
		~LossInfo(){
			print_stats();
			for (int i = 0 ; i < 2 ; i++){
				if (fclose(outfile[i])){ 
    		    	click_chatter("error closing file!");
				}
			}			
		}
		 
		void print_stats(){
		 	printf("Flow from A->B \n");
		 	printf("Total Bytes = [%u]      ", total_bytes(0));
		 	printf("Total Bytes Lost = [%u]\n",bytes_lost(0));
			printf("Total Packets = [%u]  ",packets(0));
			printf("Total Packets Lost = [%u]\n",packets_lost(0));
			printf("Total Loss Events = [%u]\n",loss_events(0));
	 	 	
			printf("Flow from B->A \n");
			printf("Total Bytes = [%u]     ", total_bytes(1));
			printf("Total Bytes Lost = [%u]\n",bytes_lost(1));
			printf("Total Packets = [%u]  ",packets(1));
			printf("Total Packets Lost = [%u]\n",packets_lost(1));
			printf("Total Loss Events = [%u]\n",loss_events(1));
		}



		timeval Search_seq_interval(unsigned start_seq, unsigned end_seq, unsigned paint){
		
			timeval tbstart = time_by_firstseq[paint].find(start_seq);
			timeval tbend = time_by_lastseq[paint].find(end_seq);
			MapInterval &ibtime = inter_by_time[paint];

				if (!tbend.tv_sec){ 
					if (!tbstart.tv_sec){ // We have a partial retransmission ...
						for (MapInterval::Iterator iter = ibtime.first(); iter; iter++){
	   						TimeInterval *tinter = const_cast<TimeInterval *>(&iter.value());
						   	if (tinter->start_byte < start_seq && tinter->end_byte > start_seq){
								return tinter->time;
							}  
							//printf("[%ld.%06ld : %u - %u ]\n",tinter->time.tv_sec, tinter->time.tv_usec, tinter->start_byte, tinter->end_byte);
	    				}
						// nothing matches (that cannot be possible, ERROR!)
						click_chatter("Error cannot find packet in flow history!:[%u:%u]",start_seq,end_seq);
						timeval tv = timeval();
						return tv;
					}
					else{
						//printf("Found in Start Byte Hash\n");
						return tbstart;
					}
					
				}		
				else{
					//printf("Found in End Byte Hash\n");
					return tbend;
				}
			
		};
		
		double timesub (timeval end_time , timeval start_time){
			return ((end_time.tv_sec-start_time.tv_sec) + 0.000001 *(end_time.tv_usec-start_time.tv_usec));
		}
				
		void calculate_loss_events(unsigned seq, unsigned seqlen, timeval time, unsigned paint){
			double curr_diff;
	   	    short int num_of_acks = acks[paint].find(seq);
			if ( seq < _max_seq[paint]){ // then we may have a new event.
				if ( seq < _last_seq[paint]){  //We have a new event ...
					timeval time_last_sent  = Search_seq_interval(seq ,seq+seqlen, paint);	
						if (prev_diff[paint] == 0){ //first time
				            prev_diff[paint] = timesub(time, time_last_sent);
							curr_diff = prev_diff[paint];
						}
						else{
							prev_diff[paint] = prev_diff[paint] < 0.000001 ? 0.000001 : prev_diff[paint];															
							curr_diff = timesub(time,time_last_sent);
							if (( doubling[paint] == 32) && (fabs(1-curr_diff/prev_diff[paint]) < 0.1)){
								printf("Doubling threshold reached %ld.%06ld \n",time.tv_sec,time.tv_sec);
							}
							else{
								if ((fabs(2.-curr_diff/prev_diff[paint]) < 0.1) && (!(num_of_acks > 3))){
									if (doubling[paint] < 1){
										doubling[paint] = prev_doubling[paint];
									}
									doubling[paint] = 2*doubling[paint];
								}
								if ((fabs(2.-curr_diff/prev_diff[paint]) > 0.1) && (!(num_of_acks > 3))){
									prev_doubling[paint] = doubling[paint];
									doubling[paint] = 0;
								}
							}
						}					
						
						if (num_of_acks > 3){ //triple dup.
							printf("We have a loss Event/CWNDCUT [Triple Dup] at time: [%ld.%06ld] seq:[%u], num_of_acks:%u \n",
								time.tv_sec, 
								time.tv_usec, 
								seq,
								num_of_acks);
								_loss_events[paint]++;
								acks[paint].insert(seq, -10000);
						}
						else{ 					
							acks[paint].insert(seq, -10000);
							doubling[paint] = doubling[paint] < 1 ? 1 : doubling[paint] ;
							printf ("We have a loss Event/CWNDCUT [Timeout] of %1.0f, at time:[%ld.%06ld] seq:[%u],num_of_acks : %hd\n",
								(log(doubling[paint])/log(2)), 
								time.tv_sec, 
								time.tv_usec, 
								seq,
								num_of_acks); 
							_loss_events[paint]++;
							prev_diff[paint] = curr_diff;
						}
				}
			}
			else{ // this is a first time send event
				
				if (_max_seq[paint] < _last_seq[paint]){
					_max_seq[paint] = _last_seq[paint];
				}
			}	
			
		};

		void calculate_loss_events2(unsigned seq, unsigned seqlen, timeval time, unsigned paint){
			double curr_diff;
	   	    short int num_of_acks = acks[paint].find(seq);
			short int  num_of_rexmt = rexmt[paint].find(seq);
			//printf("seq:%u ,rexmt: %d\n",seq , num_of_rexmt);
			if ( seq < _max_seq[paint] 
				&& (seq > _upper_wind_seq[paint] || ( num_of_rexmt > 0 ))){ // then we may have a new event.
					//printf("last_seq[%d]=%u \n",paint,seq );
					timeval time_last_sent  = Search_seq_interval(seq ,seq+seqlen, paint);	
					
					if (prev_diff[paint] == 0){ //first time
				        prev_diff[paint] = timesub(time, time_last_sent);
						curr_diff = prev_diff[paint];
					}
					else{
						prev_diff[paint] = prev_diff[paint] < 0.000001 ? 0.000001 : prev_diff[paint];															
						curr_diff = timesub(time,time_last_sent);
						if (( doubling[paint] == 32) && (fabs(1-curr_diff/prev_diff[paint]) < 0.1)){
							printf("Doubling threshold reached %ld.%06ld \n",time.tv_sec,time.tv_sec);
						}
						else{
							if ((fabs(2.-curr_diff/prev_diff[paint]) < 0.1) && (!(num_of_acks > 3))){
								if (doubling[paint] < 1){
									doubling[paint] = prev_doubling[paint];
								}
								doubling[paint] = 2*doubling[paint];
							}
							if ((fabs(2.-curr_diff/prev_diff[paint]) > 0.1) && (!(num_of_acks > 3))){
								prev_doubling[paint] = doubling[paint];
								doubling[paint] = 0;
							}
						}
					}					
					
					if (num_of_acks > 3){ //triple dup.
						printf("We have a loss Event/CWNDCUT [Triple Dup] at time: [%ld.%06ld] seq:[%u], num_of_acks:%u \n",
							time.tv_sec, 
							time.tv_usec, 
							seq,
							num_of_acks);
							_loss_events[paint]++;
							acks[paint].insert(seq, -10000);
					}
					else{ 					
						acks[paint].insert(seq, -10000);
						doubling[paint] = doubling[paint] < 1 ? 1 : doubling[paint] ;
						printf ("We have a loss Event/CWNDCUT [Timeout] of %1.0f, at time:[%ld.%06ld] seq:[%u],num_of_acks : %hd\n",
							(log(doubling[paint])/log(2)), 
							time.tv_sec, 
							time.tv_usec, 
							seq,
							num_of_acks); 
						    _loss_events[paint]++;
						prev_diff[paint] = curr_diff;
					}
					if (_max_seq[paint] > _upper_wind_seq[paint]){
						//printf("%u:%u",_last_wind_mseq[paint],_max_seq[paint]);
						_upper_wind_seq[paint] = _max_seq[paint]; // the window for this event loss
					}
					if (seq > _lower_wind_seq[paint]){
						//printf("%u:%u",_last_wind_mseq[paint],_max_seq[paint]);
						_lower_wind_seq[paint] = seq; // the window for this event loss
					}
			}
					
		};

		void calculate_loss(unsigned seq, unsigned block_size, unsigned paint){
			MapS &m_rexmt = rexmt[paint];
			if (seq < _max_seq[paint] ){  // we do a retransmission  (Bytes are lost...)
			//	printf("ok:%u:%u",seq,_max_seq[paint]);
				m_rexmt.insert(seq, m_rexmt.find(seq)+1 );					
				if (seq + block_size < _max_seq[paint]){ // are we transmiting new bytes also?
					_bytes_lost[paint] = _bytes_lost[paint] + block_size;
					
				}
				else{ // we retransmit something old
					_bytes_lost[paint] = _bytes_lost[paint] + (_max_seq[paint]-seq);
				}
				_packets_lost[paint]++;
			}
			else{ // this is a first time send event
				 // no loss normal data transfer
				_last_seq[paint] = seq+block_size;  // increase our last sequence to cover new data
			
				if (_max_seq[paint] < _last_seq[paint]){
					_max_seq[paint] = _last_seq[paint];
				}
				
			}	
			
		};
		void set_rel_seq(unsigned seq, unsigned paint){
		
			rel_seq[paint] = seq;
		
		};


		void set_last_seq(unsigned seq, unsigned paint){
		
			_last_seq[paint] = seq;
		
		};
		
		void set_last_ack(unsigned ack, unsigned paint){
		
			_last_ack[paint] = ack;
		
		};
	
		void set_total_bytes(unsigned bytes, unsigned paint){
	
			_total_bytes[paint] = bytes;
	
		};
	
		void set_packets(unsigned packets, unsigned paint){
	
			_packets[paint] = packets;
	
		};

		void inc_packets(unsigned paint){
	
			_packets[paint]++;
	
		};

		void set_lower_wind_seq(unsigned packets, unsigned paint){
	
			_lower_wind_seq[paint] = packets;
	
		};

		unsigned last_seq(unsigned paint){
		
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  

			return _last_seq[paint];
		};
		
		unsigned last_ack(unsigned paint){
		
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
		
			return _last_ack[paint];
		};
	
		unsigned total_bytes(unsigned paint){
	
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
	
			return _total_bytes[paint];
		};
	
	
		unsigned packets(unsigned paint){
			
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
	
			return _packets[paint];
		};
		
		unsigned bytes_lost(unsigned paint){
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
	
			return _bytes_lost[paint];
		};
		
		unsigned loss_events(unsigned paint){
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
	
			return _loss_events[paint];
		};		
		
		unsigned packets_lost(unsigned paint){
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
	
			return _packets_lost[paint];
		};
		unsigned lower_wind_seq(unsigned paint){
			if (paint > 2 ){
				printf("Error overflow Paint\n");		
				return 0;
			}		  
	
			return _lower_wind_seq[paint];
		};				

		
	};

};

#endif
