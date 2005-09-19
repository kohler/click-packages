#ifndef CLICK_SPLITFIRST_HH
#define CLICK_SPLITFIRST_HH
#include <click/element.hh>


/*
 * =c
 * SplitFirst(THRESHOLD)
 * =s classification
 * splits the first N packets to output port 1, to port 0 otherwise.
 * =processing
 * Push
 *
 * =d
 * SplitFirst splits the first incoming THRESHOLD packets to output port 1: this
 * behavior is useful to use only the following packets (which should 
 * represent a more "stable" flow) to statistically hook a real-time (not-RTP) flow.
 *
 * =e
 * elementclass class_stat {
 *       $first, $av_length, $av_rate, $dscp |
 *       split::SplitFirst($first);
 *       check_length::CheckAverageLength($av_length);
 *       check_rate::Meter($av_rate);
 *       set::SetIPDSCP($dscp);
 *       input->split;
 *       split[1]->[1]output;
 *       split[0]->check_length;
 *       check_length[0]->[2]output;
 *       check_length[1]->check_rate;
 *       check_rate[0]->[3]output;
 *       check_rate[1]->set->[0]output;
 *       }
 *
 * In the above example, SplitFirst is used in combination with CheckAveragelength, Meter and IPDSCP
 * elements to hook a real-time (not-RTP) flow and mark its packets' DSCP field.
 *
 * =h threshold (write-only)
 * Number of first incoming packets to filter out.
 *
 * =a CheckAverageLength, Meter, SetIPDSCP */


class SplitFirst : public Element { public:
  
  SplitFirst();
  ~SplitFirst();

  const char *class_name() const		{ return "SplitFirst"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const	        { return PUSH; }
  SplitFirst *clone() const			{ return new SplitFirst; }
 
  int configure(Vector<String> &, ErrorHandler *);
  
  void push(int port, Packet *);
 
 private:
 
 unsigned threshold,current_no_of_packets;
  

};

#endif
