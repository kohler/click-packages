// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CALCULATEFLOWS_HH
#define CLICK_CALCULATEFLOWS_HH
#include <click/element.hh>
#include <click/ipflowid.hh>
#include <click/bighashmap.hh>

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

    Packet *simple_action(Packet *);
	class LossInfo {

	private:	
		unsigned 	_src_last_seq;
		unsigned 	_src_last_ack;
		unsigned 	_src_num_of_bytes;
		unsigned	 _src_total_bytes_lost;
		unsigned	 _src_total_packets;
		
		unsigned 	_dst_last_seq;
		unsigned 	_dst_last_ack;
		unsigned 	_dst_num_of_bytes;
		unsigned	_dst_total_bytes_lost;
		unsigned	_dst_total_packets;

	public:	
		LossInfo() { 
			_src_last_seq = 0;
			_src_last_ack = 0;
			_src_num_of_bytes = 0;
			_src_total_bytes_lost = 0;
			_src_total_packets = 0;
			_dst_last_seq = 0;
			_dst_last_ack = 0;
			_dst_num_of_bytes = 0;
			_dst_total_bytes_lost = 0;
			_dst_total_packets = 0;
		};

		void calculate_loss(unsigned seq, unsigned block_size, unsigned paint){
		switch (paint) {
				case 0 : {
					if (_src_last_seq > seq ){  // we do a retransmission  (Bytes are lost...)
						if (seq + block_size < _src_last_seq){ // are we transmiting new bytes also?
							_src_total_bytes_lost = _src_total_bytes_lost + block_size;
						}
						else{ // we retransmit something old
							_src_total_bytes_lost = _src_total_bytes_lost + (_src_last_seq-seq);
							_src_last_seq = seq + block_size; // increase our last sequence to cover new data
						}
					}
					else { // no loss normal data transfer
						_src_last_seq = seq+block_size; 
					}
					break;
				}
				case 1: {
					if (_dst_last_seq > seq ){  // we do a retransmission  (Bytes are lost...)
						if (seq + block_size < _dst_last_seq){ // are we transmiting new bytes also?
							_dst_total_bytes_lost = _dst_total_bytes_lost + block_size;
						}
						else{ // we retransmit something old
							_dst_total_bytes_lost = _dst_total_bytes_lost + ( _src_last_seq - seq );
							_dst_last_seq = seq + block_size; // increase our last sequence to cover new data
						}
					}
				else { // no loss normal data transfer
						_dst_last_seq = seq+block_size; 
					}
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					break;
				}
			}
		};

		void set_last_seq(unsigned seq, unsigned paint){
			
			switch (paint) {
				case 0 : {
					_src_last_seq = seq;
					break;
				}
				case 1: {
					_dst_last_seq = seq;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					break;
				}
			}
		};
		
		void set_last_ack(unsigned ack, unsigned paint){
			switch (paint) {
				case 0 : {
					_src_last_ack = ack;
					break;
				}
				case 1: {
					_dst_last_ack = ack;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					break;
	
				}
			}
		};
	
		void set_num_of_bytes(unsigned bytes, unsigned paint){
			switch (paint) {
				case 0 : {
					_src_num_of_bytes = bytes;
					break;
				}
				case 1: {
					_dst_num_of_bytes = bytes;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					break;
				}
			}
		};
	
		void set_total_packets(unsigned packets, unsigned paint){
			switch (paint) {
				case 0 : {
					_src_total_packets = packets;
					break;
				}
				case 1: {
					_dst_total_packets = packets;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					break;
				}
			}
		};

		void inc_total_packets(unsigned paint){
			switch (paint) {
				case 0 : {
					_src_total_packets++;
					break;
				}
				case 1: {
					_dst_total_packets++;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					break;
				}
			}
		};

		unsigned last_seq(unsigned paint){
			switch (paint) {
				case 0 : {
					return _src_last_seq;
					break;
				}
				case 1: {
					return _dst_last_seq;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					return 0;
					break;
				}
			}
		};
		
		unsigned last_ack(unsigned paint){
			switch (paint) {
				case 0 : {
					return _src_last_ack;
					break;
				}
				case 1: {
					return _dst_last_ack;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					return 0;		
					break;
				}
			}
		};
	
		unsigned num_of_bytes(unsigned paint){
			switch (paint) {
				case 0 : {
					return _src_num_of_bytes;
					break;
				}
				case 1: {
					return _dst_num_of_bytes;
					break;
				}
				default: {
					printf("Error overflow Paint\n");		
					return 0;		
					break;
				}
			}
		};
	
		unsigned total_packets(unsigned paint){
			switch (paint) {
				case 0 : {
					return _src_total_packets;
					break;
				}
				case 1: {
					return _dst_total_packets;
				}
				default: {
					printf("Error overflow Paint\n");
					return 0;		 
				}
			}
		};

		unsigned total_bytes_lost(unsigned paint){
			switch (paint) {
				case 0 : {
					return _src_total_bytes_lost;
					break;
				}
				case 1: {
					return _dst_total_bytes_lost;
				}
				default: {
					printf("Error overflow Paint\n");
					return 0;		 
				}
			}
		};
	
		
		
	};
	LossInfo loss;
    
};

#endif
