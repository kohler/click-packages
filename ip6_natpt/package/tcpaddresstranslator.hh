#ifndef CLICK_TCPADDRESSTRANSLATOR_HH
#define CLICK_TCPADDRESSTRANSLATOR_HH
#include "elements/ip6/addresstranslator.hh"
#include <click/element.hh>
#include <click/timer.hh>
#include <click/hashmap.hh>
#include <click/ip6flowid.hh>
#include <click/ipflowid.hh>
#include <clicknet/ip.h>
#include <click/ip6address.hh>
#include <click/ipaddress.hh>
#include <click/vector.hh>
#include <click/elemfilter.hh>
#include <clicknet/tcp.h>
/*
* TCPAddressTranslator (AddressTranslator)
*
* Updates seq and ack numbers in TCP header when the size
* of a packet have changed.
*/
CLICK_DECLS


class TCPAddressTranslator : public Element {

  AddressTranslator *_at;
  public:

  class Mapping6;
  typedef HashMap<IP6FlowID, Mapping6 *> Map6;
  
  TCPAddressTranslator();
  ~TCPAddressTranslator();

  const char *class_name() const		{ return "TCPAddressTranslator"; }
  const char *port_count() const		{ return "2/2"; }
  const char *processing() const		{ return PUSH; }
  int configure(Vector<String> &, ErrorHandler *);

  int initialize(ErrorHandler *);
  void uninitialize();

  void push(int port, Packet *p);
  void translate_ipv4to6(Packet *p);
  void translate_ipv6to4(Packet *p);
  Mapping6 *get_mapping6(int ip_p, const IP6FlowID &) const;
  Mapping6 *get_mapping6(int ip_p,IPAddress &, unsigned short &,
IPAddress &, unsigned short &) const;
  Mapping6 *apply_create(int ip_p, const IP6FlowID &);
  Mapping6 *apply_create(IPAddress &, unsigned short &, IPAddress &,
unsigned short &);
  void cleanup(CleanupStage);

 
 private:

  Map6 _tcp_map;    //IPv6 to IPv4
  Mapping6 *_tcp_done;
  Mapping6 *_tcp_done_tail;
         
  bool _dst_anno;
  
  int _tcp_gc_interval;
  int _tcp_done_gc_interval;
  Timer _tcp_gc_timer;
  Timer _tcp_done_gc_timer;
  int _tcp_timeout_jiffies;
  int _tcp_done_timeout_jiffies;

  int _nmapping_failures;
  
  static void tcp_gc_hook(Timer *, void *);
  static void tcp_done_gc_hook(Timer *, void *);

  protected:

    void clear_map6(Map6 &);
    void clean_map6(Map6 &, uint32_t last_jif);
    void clean_map6_free_tracked(Map6 &, Mapping6 *&free_head, Mapping6 *&free_tail, uint32_t last_jif);
    void incr_clean_map6_free_tracked(Map6 &, Mapping6 *&head, Mapping6 *&tail, uint32_t last_jif);


};


class TCPAddressTranslator::Mapping6 {

 public:

  Mapping6();
  void initialize(const IP6FlowID & new_flow) { _mapto = new_flow; }
  void initialize(int ip_p, const IP6FlowID &, const IP6FlowID &,int,
bool, Mapping6 *);
  static void make_pair(int ip_p, const IP6FlowID &, const IP6FlowID
&,Mapping6 *, Mapping6 *);


  const IP6FlowID &flow_id() const    {  return _mapto;        }
  unsigned short sport() const        { return _mapto.sport(); }
  unsigned short dport() const        { return _mapto.dport(); }
  Mapping6 * get_next()                { return _next; }
  Mapping6 * get_prev()                { return _prev; }
  void set_next(Mapping6 * next)       { _next = next; }
  void set_prev(Mapping6 * prev)       { _prev = prev; }
  Mapping6 *free_next() const		{ return _free_next; }
  void set_free_next(Mapping6 *m)      {_free_next = m;}
  int output() const 			{ return _output; }

    bool is_primary() const		{ return !_is_reverse; }
    const Mapping6 *primary() const { return is_primary() ? this : _reverse; }
    Mapping6 *primary()		   { return is_primary() ? this : _reverse; }

    Mapping6 *reverse() const		{ return static_cast<Mapping6 *>(_reverse); }

    int update_seqno_delta(tcp_seq_t old_seqno, int32_t delta);
    int32_t delta_for(tcp_seq_t) const;
    int32_t delta_for2(tcp_seq_t) const;

    bool session_over() const		{ return _flow_over && _reverse->_flow_over; }
    void set_session_over()		{ _flow_over = _reverse->_flow_over = true; }
    void set_session_flow_over()	{ _flow_over = true; }
    void clear_session_flow_over()	{ _flow_over = false; }

    bool free_tracked() const		{ return _free_tracked; }
    void add_to_free_tracked_tail(Mapping6 *&head, Mapping6 *&tail);
    void clear_free_tracked();

    void apply(int p,Packet *p);
    String s() const;

    bool used_since(uint32_t) const;


 protected:

  tcp_seq_t _trigger;
  int32_t _delta;
  tcp_seq_t _old_delta;

  void change_udp_csum_delta(unsigned old_word, unsigned new_word);

  uint16_t _ip_csum_delta;
  uint16_t _udp_csum_delta;

 
  //long unsigned int _t;
  IP6FlowID _mapto;
  Mapping6 *_prev;
  Mapping6 *_next;
  Mapping6 *_free_next;


    Mapping6 *_reverse;

    bool _is_reverse : 1;
    bool _marked : 1;
    bool _flow_over : 1;
    bool _free_tracked : 1;
    bool _dst_anno : 1;
    uint8_t _output;
    uint8_t _ip_p;
    unsigned _used;

    void append_to_free(Mapping6 *&head, Mapping6 *&tail);
    inline Mapping6 *free_from_list(Map6 &, bool notify);

  friend class TCPAddressTranslator;
};


 
inline void
TCPAddressTranslator::Mapping6::append_to_free(Mapping6 *&head,
Mapping6 *&tail)
{
  assert((!head && !tail) || (head && tail && head->_free_tracked && tail->_free_tracked));
  assert(!_free_next && !_reverse->_free_next);
  if (tail)
	  tail = tail->_free_next = this;
  else
	  head = tail = this;
}

inline void
TCPAddressTranslator::Mapping6::add_to_free_tracked_tail(Mapping6
*&head, Mapping6 *&tail)
{
  assert(!_free_tracked && !_reverse->_free_tracked);
  _free_tracked = _reverse->_free_tracked = true;
  primary()->append_to_free(head, tail);
}

inline void
TCPAddressTranslator::Mapping6::clear_free_tracked()
{
  _free_tracked = _reverse->_free_tracked = false;
  _free_next = 0;
  assert(_reverse->_free_next == 0);
}

inline TCPAddressTranslator::Mapping6 *
TCPAddressTranslator::get_mapping6(int ip_p, const IP6FlowID &in)
const
{
  if (ip_p == IP_PROTO_TCP)
    return static_cast<Mapping6 *>(_tcp_map[in]);
  else
    return 0;
}

inline TCPAddressTranslator::Mapping6 *
TCPAddressTranslator::get_mapping6(int ip_p,IPAddress &ip_src,
unsigned short &sport, IPAddress &ip_dst, unsigned short &dport)
const
{
    if (ip_p == IP_PROTO_TCP)
    {
      IP6Address ip6_src;
      IP6Address ip6_msrc = IP6Address(ip_src);
      IP6Address ip6_dst  = IP6Address(ip_dst);
      unsigned short xsport=0;
      unsigned short  ssport = sport;
      unsigned short  ddport = dport;
      
      IP6FlowID flow(ip6_msrc,ssport,ip6_dst,ddport);

      if (_at->lookup(ip6_src, xsport, ip6_msrc, ssport, ip6_dst, ddport,1))
      {
        flow.set_saddr(ip6_src);
      }

      return static_cast<Mapping6 *>(_tcp_map[flow]);
    }
    else
      return 0;
}

inline int32_t
TCPAddressTranslator::Mapping6::delta_for(tcp_seq_t seqno) const
{
  return (SEQ_GEQ(seqno, _trigger) ? _delta : _old_delta);
}

inline int32_t
TCPAddressTranslator::Mapping6::delta_for2(tcp_seq_t seqno) const
{
  return _delta;
}

inline bool
TCPAddressTranslator::Mapping6::used_since(uint32_t t) const
{
  return ((int32_t)(_used - t)) >= 0 || ((int32_t)(_reverse->_used - t)) >= 0;
}

CLICK_ENDDECLS
#endif

