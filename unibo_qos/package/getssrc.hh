#ifndef GETSSRC_HH
#define GETSSRC_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

/*
 * =c
 * GetSSRC(OFFSET)
 * =s classification
 * splits packets _possibly_ containing an SSRC field (used by the RTP protocol): this is copied it inside the packet annotation field
 * =processing
 * Push
 *
 * =d
 * GetSSRC has two output ports. All incoming packets _possibly_ having an SSRC field
 * marked up are directed to output port 0, any remaining packets are emitted on
 * output port 1 (since they cannot absolutely pertain to an RTP flow).
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
 * In the above example, GetSSRC is used in combination with the RTPClassifier and SetIPDSCP elements
 * to hook an RTP flow and mark its packets' DSCP field.
 *    
 * =h SSRC offset in bytes (write-only)
 * Offset (in bytes) of the SSRC field from the beginning of the Ethernet datagram (50 bytes).
 * See also RFC 3550.
 *
 * =a RTPClassifier, SetIPDSCP */


class GetSSRC : public Element {
  
  unsigned _offset;
  uint8_t _ssrc,i;
  
 public:
  
  GetSSRC();
  ~GetSSRC();
  
  const char *class_name() const		{ return "GetSSRC"; }
  const char *port_count() const		{ return "1/2"; }
  const char *processing() const		{ return AGNOSTIC; }
  
  GetSSRC *clone() const			{ return new GetSSRC; }
  int configure(Vector<String> &, ErrorHandler *);

  void push(int,Packet *);
  
};

#endif
