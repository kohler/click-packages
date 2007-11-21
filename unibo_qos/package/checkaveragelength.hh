#ifndef CLICK_CHECKAVERAGELENGTH_HH
#define CLICK_CHECKAVERAGELENGTH_HH
#define ELM 15 		// number of packets to use to calculate the average
#include <click/element.hh>

/*
 * =c
 * CheckAverageLength(MINLENGTH)
 * =s classification
 * splits a flow of packets depending on their average length.
 * =processing
 * Push
 *
 * =d
 * CheckAverageLength splits packets depending on the average length of the last ELM packets received.
 * Only if packets' average lenght is less than the value of MINLENGTH, they get out from output port 1
 * (thus they could pertain to a real-time flow), from port 0 otherwise.
 *
 * (ELM = 15 packets).
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
 * In the above example, CheckAverageLength is used in combination with the SplitFirst, Meter and SetIPDSCP elements
 * to hook a real-time (not-RTP) flow and mark its packets' DSCP field.
 *
 * =h min (write-only)
 * Minimum average length (in bytes) of packets to filter out.
 *
 * =a SplitFirst, Meter, SetIPDSCP */
				

class CheckAverageLength : public Element { public:
  
  CheckAverageLength();
  ~CheckAverageLength();
  
  const char *class_name() const		{ return "CheckAverageLength"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const		{ return PUSH; }
  
  CheckAverageLength *clone() const			{ return new CheckAverageLength; }
  
  int configure(Vector<String> &, ErrorHandler *);
  
  void media();
  void ins(unsigned);
  unsigned average();

  void push(int, Packet *);
 
 private:

  unsigned a[ELM];
  unsigned min,av_length,cont; 

};

#endif
