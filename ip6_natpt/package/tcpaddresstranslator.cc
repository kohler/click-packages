/*
 * tcpaddresstranslator.{cc,hh} -- updates seq and ack numbers in packets
 * Fabian Gonzalez <fabiang99@hoptmail.com>
 * Pontificia Universidad Javeriana
 * Bogota - Colombia 2002.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#include <click/config.h>
#include "tcpaddresstranslator.hh"
#include <clicknet/ip6.h>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/llrpc.h>
#include <click/router.hh>
#include <click/integers.hh>
CLICK_DECLS

#ifdef CLICK_LINUXMODULE
extern "C" {
#include <asm/softirq.h>
#include <net/sock.h>
}
#endif



//Mapping

TCPAddressTranslator::Mapping6::Mapping6()
  :  _trigger(0), _delta(0), _old_delta(0),
    _prev(0), _next(0), _free_next(0), _is_reverse(false),
_marked(false),
    _flow_over(false), _free_tracked(false),_ip_p(0)
{
}

int
TCPAddressTranslator::Mapping6::update_seqno_delta(tcp_seq_t trigger,
int32_t d)
{
  if (SEQ_LEQ(trigger, _trigger) && (_trigger || _delta || _old_delta))
    return -1;
  else
  {
    _old_delta = _delta;
    _trigger = trigger;
    _delta += d;
    _used = 0;
    return 0;
  }
}


void
TCPAddressTranslator::Mapping6::change_udp_csum_delta(unsigned
old_word, unsigned new_word)
{
  const uint16_t *source_words = (const unsigned short *)&old_word;
  const uint16_t *dest_words = (const unsigned short *)&new_word;
  uint32_t delta = _udp_csum_delta;
  for (int i = 0; i < 2; i++) {
    delta += ~source_words[i] & 0xFFFF;
    delta += dest_words[i];
  }
  // why is this required here, but not elsewhere when we do
  // incremental updates?
  if ((int)ntohl(old_word) >= 0 && (int)ntohl(new_word) < 0)
    delta -= htons(1);
  else if ((int)ntohl(old_word) < 0 && (int)ntohl(new_word) >= 0)
    delta += htons(1);
  delta = (delta & 0xFFFF) + (delta >> 16);
  _udp_csum_delta = delta + (delta >> 16);  
}
 

void
TCPAddressTranslator::uninitialize()
{
    
}

int
TCPAddressTranslator::initialize(ErrorHandler *)
{
  _tcp_gc_timer.initialize(this);
  _tcp_gc_timer.schedule_after_s(_tcp_gc_interval);
  _tcp_done_gc_timer.initialize(this);
  _tcp_done_gc_timer.schedule_after_s(_tcp_done_gc_interval);
  _nmapping_failures = 0;
  return 0;
}

TCPAddressTranslator::TCPAddressTranslator()
  : _tcp_map(0), _tcp_done(0),
_tcp_done_tail(0),_tcp_gc_timer(tcp_gc_hook, this),
    _tcp_done_gc_timer(tcp_done_gc_hook, this)
{
  MOD_INC_USE_COUNT;
  add_input(); /*IPv4 arriving packets */
  add_input(); /*IPv6 arriving packets */
  add_output(); /* IPv4 outgoing translated packets*/
  add_output(); /* IPv6 outgoing translated packets*/
} 


TCPAddressTranslator::~TCPAddressTranslator()
{
  MOD_DEC_USE_COUNT;
  assert(!_tcp_gc_timer.scheduled() && !_tcp_done_gc_timer.scheduled());
}

int
TCPAddressTranslator::configure(Vector<String> &conf,
ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("wrong number of arguments; expected `TCPAddressTranslator(AddressTranslator element)'");

  int before = errh->nerrors();

  // get AddressTranslator
  Element *e = cp_element(conf[0], this, errh);
  if (!e)
    return -1;
  _at = (AddressTranslator *)e->cast("AddressTranslator");
  if (! _at)
    return errh->error("second argument must be an AddressTranslator element");

  
  // numbers in seconds
  _tcp_timeout_jiffies = 86400;		// 24 hours
  _tcp_done_timeout_jiffies = 240;	// 4 minutes
  _tcp_gc_interval = 3600;		// 1 hour
  _tcp_done_gc_interval = 10;		// 10 seconds
  _dst_anno = true;

/*  if (cp_va_parse_remove_keywords
      (conf, 0, this, errh,
       "REAP_TCP", cpSeconds, "reap interval for active TCP connections", &_tcp_gc_interval,
       "REAP_TCP_DONE", cpSeconds, "reap interval for completed TCP connections", &_tcp_done_gc_interval,
       "TCP_TIMEOUT", cpSeconds, "TCP timeout interval", &_tcp_timeout_jiffies,
       "TCP_DONE_TIMEOUT", cpSeconds, "completed TCP timeout interval", &_tcp_done_timeout_jiffies,
       "DST_ANNO", cpBool, "set destination IP addr annotation?", &_dst_anno,0) < 0)
    return -1;
  */
  set_ninputs(2);

  // change timeouts into jiffies
  _tcp_timeout_jiffies *= CLICK_HZ;
  _tcp_done_timeout_jiffies *= CLICK_HZ;

  if (errh->nerrors() == before)
    return 0;
  else {
    uninitialize();
    return -1;
  }
}


void
TCPAddressTranslator::push(int port, Packet *p)
{
  if (port == 0)
    translate_ipv6to4(p);
  else
    translate_ipv4to6(p);
}

void
TCPAddressTranslator::translate_ipv6to4(Packet *p)
{

  const click_ip *iph = (click_ip *)p->data();
  click_tcp *tcph = (click_tcp *)(iph + 1);

  IP6Address ip6_src;
  IP6Address ip6_msrc = IP6Address(IPAddress(iph->ip_src));
  IP6Address ip6_dst = IP6Address(IPAddress(iph->ip_dst));

  unsigned short sport=0;

  unsigned short ssport = tcph->th_sport;
  unsigned short ddport = tcph->th_dport;

  IP6FlowID flow6(ip6_msrc,ssport,ip6_dst,ddport);

  if (_at->lookup(ip6_src, sport, ip6_msrc, ssport, ip6_dst, ddport,1))
  {
    flow6.set_saddr(ip6_src);
  }
  else
  {
    click_chatter("LOOKUP FAILED: Cannot update seq. numbers!");
  }

  Mapping6 *m = static_cast<Mapping6 *>(_tcp_map.find(flow6));

  if (!m)
  {			// create new mapping
    m = TCPAddressTranslator::apply_create(0, flow6);
  }

  else if(!m)
    {
      p->kill();
      return;
    }
  m->apply(0,p);
  output(0).push(p);

  // add to list for dropping TCP connections faster
  if (!m->free_tracked() && (tcph->th_flags & (TH_FIN | TH_RST))
      && m->session_over())
    m->add_to_free_tracked_tail(_tcp_done, _tcp_done_tail);
}


void
TCPAddressTranslator::translate_ipv4to6(Packet *p)
{
  click_ip6 *iph = (click_ip6 *)p->data();
  click_tcp *tcph = (click_tcp *)(iph + 1);
  IP6Address ip6_sr = IP6Address(iph->ip6_src);
  IP6Address ip6_ds = IP6Address(iph->ip6_dst);

  unsigned  short ssport = tcph->th_sport;
  unsigned  short ddport = tcph->th_dport;
  IP6FlowID flow(ip6_sr,ssport,ip6_ds,ddport);
  Mapping6 *m = static_cast<Mapping6 *>(_tcp_map.find(flow));

  if (!m)
  {			// create new mapping
    m = TCPAddressTranslator::apply_create(1, flow);
  }
  if(!m)
  {
    p->kill();
    return;
  }
  m->apply(1,p);
  output(1).push(p);

  // add to list for dropping TCP connections faster
  if (!m->free_tracked() && (tcph->th_flags & (TH_FIN | TH_RST))
      && m->session_over())
    m->add_to_free_tracked_tail(_tcp_done, _tcp_done_tail);
}



void
TCPAddressTranslator::Mapping6::apply(int protocol,Packet *p_in)
{
  WritablePacket *p = p_in->uniqueify();
  // TCP header

  if(protocol==0) //Handling of IPv4 packets
  {
    click_ip *iph = (click_ip *)p->data();
    click_tcp *tcph = (click_tcp *)(iph + 1);
    uint32_t csum_delta = _udp_csum_delta;
    uint32_t oldval = ntohl(tcph->th_seq);
    uint32_t newval = htonl(oldval + delta_for(oldval));

    if (tcph->th_seq != newval)
    {
      csum_delta += (~tcph->th_seq >> 16) + (~tcph->th_seq & 0xFFFF)
        + (newval >> 16) + (newval & 0xFFFF);
      tcph->th_seq = newval;
    }

    oldval = ntohl(tcph->th_ack);
    newval = htonl(oldval - reverse()->delta_for(oldval));
    if (tcph->th_ack != newval)
    {
      csum_delta += (~tcph->th_ack >> 16) + (~tcph->th_ack & 0xFFFF)
        + (newval >> 16) + (newval & 0xFFFF);
      tcph->th_ack = newval;
    }

    // update checksum
    uint32_t sum2 = (~tcph->th_sum & 0xFFFF) + csum_delta;
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    tcph->th_sum = ~(sum2 + (sum2 >> 16));

    // check for session ending flags
    if (tcph->th_flags & TH_RST)
      set_session_over();
    else if (tcph->th_flags & TH_FIN)
      set_session_flow_over();
    else if (tcph->th_flags & TH_SYN)
      clear_session_flow_over();
  }
  else     //Handling of IPv4 packets
  {
    click_ip6 *iph = (click_ip6 *)p->data();
    click_tcp *tcph = (click_tcp *)(iph + 1);
    uint32_t csum_delta = _udp_csum_delta;
    uint32_t oldval = ntohl(tcph->th_seq);
    uint32_t newval = htonl(oldval + delta_for(oldval));

    if (tcph->th_seq != newval)
    {
      csum_delta += (~tcph->th_seq >> 16) + (~tcph->th_seq & 0xFFFF)
        + (newval >> 16) + (newval & 0xFFFF);
      tcph->th_seq = newval;
    }

    oldval = ntohl(tcph->th_ack);
    if (_reverse->_used == 0)
    {
			newval = htonl(oldval - reverse()->delta_for2(oldval));
			_used++;		
		}
		else
		{
			newval = htonl(oldval - reverse()->delta_for(oldval));
		}
    if (tcph->th_ack != newval)
    {
      csum_delta += (~tcph->th_ack >> 16) + (~tcph->th_ack & 0xFFFF)
        + (newval >> 16) + (newval & 0xFFFF);
      tcph->th_ack = newval;
    }
    // update checksum
    uint32_t sum2 = (~tcph->th_sum & 0xFFFF) + csum_delta;
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    tcph->th_sum = ~(sum2 + (sum2 >> 16));

    // check for session ending flags
    if (tcph->th_flags & TH_RST)
      set_session_over();
    else if (tcph->th_flags & TH_FIN)
      set_session_flow_over();
    else if (tcph->th_flags & TH_SYN)
      clear_session_flow_over();
    
  }
}


void
TCPAddressTranslator::Mapping6::initialize(int ip_p, const IP6FlowID
&in, const IP6FlowID &out,
			   int output,bool is_reverse, Mapping6 *reverse)
{
  // set fields
  _ip_p = ip_p;
  _mapto = out;
  _is_reverse = is_reverse;
  _reverse = reverse;
  _output = output;

  // set checksum deltas
  const unsigned short *source_words = (const unsigned short *)&in;
  const unsigned short *dest_words = (const unsigned short *)&_mapto;
  unsigned delta = 0;
  for (int i = 0; i < 4; i++) {
    delta += ~source_words[i] & 0xFFFF;
    delta += dest_words[i];
  }
  delta = (delta & 0xFFFF) + (delta >> 16);
  _ip_csum_delta = delta + (delta >> 16);

  for (int i = 4; i < 6; i++) {
    delta += ~source_words[i] & 0xFFFF;
    delta += dest_words[i];
  }
  delta = (delta & 0xFFFF) + (delta >> 16);
  _udp_csum_delta = delta + (delta >> 16);
}

void
TCPAddressTranslator::Mapping6::make_pair(int ip_p, const IP6FlowID
&inf, const IP6FlowID &outf,
			 Mapping6 *in_map, Mapping6 *out_map)
{
  in_map->initialize(ip_p, inf, outf,0, false, out_map);
  out_map->initialize(ip_p, outf.rev(),inf.rev(),1, true, in_map);
}

TCPAddressTranslator::Mapping6 *
TCPAddressTranslator::apply_create(IPAddress &ip_src, unsigned short
&sport, IPAddress &ip_dst, unsigned short &dport)
{
    IP6Address ip6_src;
    IP6Address ip6_msrc = IP6Address(ip_src);
    IP6Address ip6_dst  = IP6Address(ip_dst);

    unsigned short xsport=0;

    unsigned short ssport = sport;
    unsigned short ddport = dport;

    IP6FlowID flow(ip6_msrc,ssport,ip6_dst,ddport);

  if (_at->lookup(ip6_src, xsport, ip6_msrc, ssport, ip6_dst, ddport,1))
  {
    //crear flowid ipv6
    flow.set_saddr(ip6_src);
  }
  else
  {
    click_chatter("LOOKUP FAILED: Cannot update seq. numbers!");
  }


    Mapping6 *forward = new TCPAddressTranslator::Mapping6();
    Mapping6 *reverse = new TCPAddressTranslator::Mapping6();

    if (forward && reverse) {
      Mapping6::make_pair(0,flow, flow,forward, reverse);

      IP6FlowID reverse_flow = forward->flow_id().rev();
      _tcp_map.insert(flow, forward);
      _tcp_map.insert(reverse_flow, reverse);
     return forward;
    }
    else
    {
      _nmapping_failures++;
      delete forward;
      delete reverse;
      return 0;

    }

}


TCPAddressTranslator::Mapping6 *
TCPAddressTranslator::apply_create(int ip_p, const IP6FlowID &flow)
{
    Mapping6 *forward = new TCPAddressTranslator::Mapping6();
    Mapping6 *reverse = new TCPAddressTranslator::Mapping6();

    if (forward && reverse) {
      Mapping6::make_pair(0,flow, flow,forward, reverse);

      IP6FlowID reverse_flow = forward->flow_id().rev();
      _tcp_map.insert(flow, forward);
      _tcp_map.insert(reverse_flow, reverse);
     return forward;
    }
    else
    {
      _nmapping_failures++;
      delete forward;
      delete reverse;
      return 0;

    }

}

void
TCPAddressTranslator::tcp_gc_hook(Timer *timer, void *thunk)
{
  TCPAddressTranslator *rw = (TCPAddressTranslator *)thunk;
  rw->clean_map6(rw->_tcp_map, click_jiffies() -
rw->_tcp_timeout_jiffies);
  timer->reschedule_after_s(rw->_tcp_gc_interval);
}

void
TCPAddressTranslator::tcp_done_gc_hook(Timer *timer, void *thunk)
{
  TCPAddressTranslator *rw = (TCPAddressTranslator *)thunk;
  rw->clean_map6_free_tracked(rw->_tcp_map, rw->_tcp_done,
rw->_tcp_done_tail,click_jiffies() -
rw->_tcp_done_timeout_jiffies);
  timer->reschedule_after_s(rw->_tcp_done_gc_interval);
}

void
TCPAddressTranslator::clean_map6(Map6 &table, uint32_t last_jif)
{
    Mapping6 *to_free = 0;

		for (Map6::iterator iter = table.begin(); iter; iter++)
	if (Mapping6 *m = iter.value()) {
	    if (m->is_primary() && !m->used_since(last_jif) &&
!m->free_tracked()) {
		m->set_free_next(to_free);
		to_free = m;
	    }
	}

    while (to_free)
	to_free = to_free->free_from_list(table, true);
}

inline TCPAddressTranslator::Mapping6 *
TCPAddressTranslator::Mapping6::free_from_list(Map6 &map, bool notify)
{
    // see also clear_map below
    Mapping6 *next = _free_next;
    //map.remove(reverse()->flow_id().rev());
    //map.remove(flow_id().rev());
    delete reverse();
    delete this;
    return next;
} 

void
TCPAddressTranslator::incr_clean_map6_free_tracked(Map6
&table,Mapping6 *&free_head, Mapping6 *&free_tail,uint32_t last_jif)
{
    Mapping6 *m = free_head;
    if (!m->session_over()) {
	// has been recycled; remove from free-tracked list
	free_head = m->free_next();
	if (!free_head)
	    free_tail = 0;
	m->clear_free_tracked();
    } else if (m->used_since(last_jif)) {
	// recently used; cycle to end of list
	if (m->free_next()) {
	    free_head = m->free_next();
	    m->set_free_next(0);
	    m->append_to_free(free_head, free_tail);
	}
    } else {
	// actually free; delete it
	free_head = m->free_from_list(table, true);
	if (!free_head)
	    free_tail = 0;
    }
}  

void
TCPAddressTranslator::clear_map6(Map6 &table)
{
    Mapping6 *to_free = 0;

    for (Map6::iterator iter = table.begin(); iter; iter++) {
	Mapping6 *m = iter.value();
	if (m->is_primary()) {
	    m->set_free_next(to_free);
	    to_free = m;
	}
    }

    while (to_free) {
	// don't call free_from_list, because there is no need to update
	// 'table' incrementally
	Mapping6 *next = to_free->free_next();
	delete to_free->reverse();
	delete to_free;
	to_free = next;
    }

    table.clear();
} 

void
TCPAddressTranslator::clean_map6_free_tracked(Map6 &table, Mapping6
*&free_head, Mapping6 *&free_tail,uint32_t last_jif)
{
  Mapping6 *free_list = free_head;
  Mapping6 **prev_ptr = &free_list;

  Mapping6 *m = free_list;
  while (m)
  {
	  Mapping6 *next = m->free_next();
  	if (!m->session_over())
    {
	    // reuse of a port; take it off the free-tracked list
	    *prev_ptr = next;
	    m->clear_free_tracked();
	  }
    else if (m->used_since(last_jif))
	    break;
	  else
	    prev_ptr = &m->_free_next;
  	m = next;
  }

  // cut off free_list before 'm'
  *prev_ptr = 0;

  // move free_head forward, to 'm' or beyond
  if (m && m->free_next())
  {
	  // if 'm' exists, then shift it to the end of the list
  	free_head = m->free_next();
	  m->set_free_next(0);
  	m->append_to_free(free_head, free_tail);
  }
  else
	  free_head = free_tail = m;

  // free contents of free_list
  while (free_list)
  	free_list = free_list->free_from_list(table, true);
}

void
TCPAddressTranslator::cleanup(CleanupStage)
{
  clear_map6(_tcp_map);
}

String
TCPAddressTranslator::Mapping6::s() const
{
  StringAccum sa;
  sa << reverse()->flow_id().rev().s() << " => " << flow_id().s()
     << " seq " << (_delta > 0 ? "+" : "") << _delta
     << " [" + String(output()) + "]";
  return sa.take_string();
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(ip6)
EXPORT_ELEMENT(TCPAddressTranslator)
