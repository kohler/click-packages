#ifndef CLICK_RTPCLASSIFIER_HH
#define CLICK_RTPCLASSIFIER_HH

#define MAX 20 	// table rows
#define COL 5 	// table columns
#define NRTP 3 	// max number of managed flows per each Service Level Agreement (SLA)
#define TIMEOUT 2
#define TIMEOUTRTP 30
#define ERROR 1000
#define NORTP 20000

#include <click/element.hh>


/*
 * =c
 * RTPClassifier
 * =s classification
 * splits packets pertaining to an RTP flow from other BE traffic.
 * =processing
 * Push
 *
 * =d
 * Flows are classified as RTP if 6 following packets containing the
 * same SSRC field are received before TIMEOUT seconds.
 * If not, flow is not classified. Once a flow is classified, it can 
 * be cancelled if no more packets (with the same SSRC value) are 
 * received for TIMEOUTRTP seconds.
 * (TIMEOUT = 2 seconds, TIMEOUTRTP = 30 seconds).
 *
 * RTP packets get out from output port 0, others from output port 1.
 * RTPClassifier[0]-> RTP traffic
 * RTPClassifier[1]-> non-RTP traffic *
 *
 * =e
 * elementclass class_RTP {
 *    $ssrc, $dscp |
 *    get::GetSSRC($ssrc);
 *    rtp::RTPClassifier;
 *    set::SetIPDSCP($dscp);
 *    input->get[0]->rtp;
 *    get[1]->[1]output;
 *    rtp[0]->set->[0]output;
 *    rtp[1]->[1]output;
 *    }
 *
 * In the above example, RTPClassifier is used in combination with the GetSSRC and SetIPDSCP elements
 * to hook an RTP flow and mark its packets' DSCP field.
 *
 * =a GetSSRC, SetIPDSCP */


class RTPClassifier : public Element { 
  
 private:
  
  unsigned table[MAX][COL];
  unsigned tabrtp[NRTP][COL];
  
 public:
  
  RTPClassifier();
  ~RTPClassifier();

  const char *class_name() const		{ return "RTPClassifier"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const	        { return PUSH; }
  RTPClassifier *clone() const	        { return new RTPClassifier; }
  
  void FlowTable();
  void del_old_flow(unsigned);
  unsigned ins_flow(unsigned,unsigned);
  unsigned ins_flow_rtp(unsigned,unsigned);
  bool is_rtp(unsigned);

  void add_handlers();
    
  void push(int,Packet *);
  
};

#endif

