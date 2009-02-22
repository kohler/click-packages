/*
 * snmptrapsource.{cc,hh} -- element generates SNMP traps
 * Eddie Kohler
 *
 * Copyright (c) 2001 Mazu Networks, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "snmptrapsource.hh"
#include "snmpbasics.hh"
#include "snmpber.hh"
#include "snmpvarinfo.hh"
#include <click/router.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

// NOTE: Cannot send packets directly from a handler because of SMP concerns.
// So we put the packets onto an internal queue, then emit them through
// run_task().

SNMPTrapSource::SNMPTrapSource()
  : _task(this)
{
  _head = _tail = 0;
  _capacity = QSIZE;
}

SNMPTrapSource::~SNMPTrapSource()
{
}

void *
SNMPTrapSource::cast(const char *n)
{
  if (strcmp(n, "Storage") == 0)
    return (Storage *)this;
  else if (strcmp(n, "SNMPTrapSource") == 0)
    return (Element *)this;
  else
    return 0;
}

int
SNMPTrapSource::add_trap(const String &str, ErrorHandler *errh)
{
  Vector<String> words;
  String name;
  cp_spacevec(str, words);
  if (words.size() < 1 || !cp_word(words[0], &name))
    return errh->error("should be 'NAME [SPECIFIC] [VARIABLES...]'");

  int first_var = 1;
  int trap_type;
  if (name == "coldStart")
    trap_type = 0;
  else if (name == "warmStart")
    trap_type = -1;
  else if (name == "linkDown")
    trap_type = -2;
  else if (name == "linkUp")
    trap_type = -3;
  else if (name == "authenticationFailure")
    trap_type = -4;
  else if (name == "egpNeighborLoss")
    trap_type = -5;
  else {
    if (words.size() < 2 || !cp_integer(words[1], &trap_type))
      trap_type = -6;
    else if (trap_type < 0)
      return errh->error("specific trap code must be >= 0");
    else {
      if (trap_type == 0) trap_type = -6;
      first_var = 2;
    }
  }

  int snmp_var;
  _names.push_back(name);
  _offsets.push_back(_snmp_vars.size());
  _trap_types.push_back(trap_type);
  for (int j = first_var; j < words.size(); j++)
    if (!cp_snmp_variable(words[j], this, &snmp_var, errh))
      errh->error("'%s' is not an SNMP variable", words[j].c_str());
    else
      _snmp_vars.push_back(snmp_var);

  return 0;
}

int
SNMPTrapSource::configure(Vector<String> &conf, ErrorHandler *errh)
{
  Vector<String> traps;
  _src = _dst = IPAddress();
  _sport = 0;
  _dport = 162;
  _community = "public";
  _udp_encap = true;
  _ip_ttl = 255;
  _active = true;
  
  if (cp_va_kparse(conf, this, errh,
		   "UDP", 0, cpBool, &_udp_encap,
		   "TTL", 0, cpByte, &_ip_ttl,
		   "SRC", 0, cpIPAddress, &_src,
		   "SPORT", 0, cpUDPPort, &_sport,
		   "DST", 0, cpIPAddress, &_dst,
		   "DPORT", 0, cpUDPPort, &_dport,
		   "COMMUNITY", 0, cpString, &_community,
		   "ENTERPRISE", cpkM, cpSNMPOid, &_enterprise,
		   "TRAP", 0, cpArguments, &traps,
		   "ACTIVE", 0, cpBool, &_active,
		   cpEnd) < 0)
    return -1;

  if (_udp_encap && (!_src || !_dst))
    return errh->error("must specify source and destination addresses");
  if (_udp_encap && (!_sport || !_dport))
    return errh->error("must specify source and destination ports");
  if (_enterprise.size() == 0)
    return errh->error("must specify enterprise SNMP OID");
  if (traps.size() == 0)
    errh->warning("no TRAP specifications");
  _agent = _src;

  int before = errh->nerrors();
  for (int i = 0; i < traps.size(); i++) {
      PrefixErrorHandler cerrh(errh, "TRAP " + String(i+1) + ": ");
      add_trap(traps[i], &cerrh);
  }
  _offsets.push_back(_snmp_vars.size());
  return (errh->nerrors() == before ? 0 : -1);
}

int
SNMPTrapSource::initialize(ErrorHandler *)
{
  _task.initialize(this, false);
  _jiffies0 = snmp_time_ticks_since(0);
  _id = click_random();
  return 0;
}

void
SNMPTrapSource::cleanup(CleanupStage)
{
  for (int i = _head; i != _tail; i = next_i(i))
    _queue[i]->kill();
}

int
SNMPTrapSource::generate_trap(int trap)
{
  if (!_active)
    return 0;
    
  SNMPBEREncoder ber;

  ber.push_long_sequence();

  ber.encode_integer(SNMP_VERSION_1);
  ber.encode_octet_string(_community);
  
  ber.push_long_sequence(SNMP_TAG_V1_TRAP);
  ber.encode_snmp_oid(_enterprise);
  ber.encode_ip_address(_agent);
  if (_trap_types[trap] <= 0) {
    ber.encode_integer(-_trap_types[trap]);
    ber.encode_integer(0);
  } else {
    ber.encode_integer(6 /* enterpriseSpecific */);
    ber.encode_integer(_trap_types[trap]);
  }

  ber.encode_time_ticks(snmp_time_ticks_since(_jiffies0));

  ber.push_long_sequence();
  for (int i = _offsets[trap]; i < _offsets[trap+1]; i++)
    SNMPVariableInfo::encode_binding(_snmp_vars[i], ber, this);
  ber.pop_sequence();
  ber.pop_sequence();
  ber.pop_sequence();

  // check for out-of-memory condition
  if (ber.memory_error()) {
    _drops++;
    return -ENOMEM;
  }

  WritablePacket *p;
  if (_udp_encap)
    p = Packet::make(ber.length() + sizeof(click_ip) + sizeof(click_udp));
  else
    p = Packet::make(ber.length());
  if (!p) {
    _drops++;
    return -ENOMEM;
  }

  if (_udp_encap) {
    click_ip *iph = (click_ip *)p->data();
    iph->ip_v = 4;
    iph->ip_hl = sizeof(click_ip) >> 2;
    iph->ip_len = htons(p->length());
    iph->ip_id = htons(_id.fetch_and_add(1));
    iph->ip_p = IP_PROTO_UDP;
    iph->ip_src = _src;
    iph->ip_dst = _dst;
    iph->ip_tos = 0;
    iph->ip_off = 0;
    iph->ip_ttl = _ip_ttl;

    iph->ip_sum = 0;
#if HAVE_FAST_CHECKSUM
    iph->ip_sum = ip_fast_csum((unsigned char *)iph, sizeof(click_ip) >> 2);
#else
    iph->ip_sum = click_in_cksum((unsigned char *)iph, sizeof(click_ip));
#endif

    p->set_dst_ip_anno(_dst);
    p->set_ip_header(iph, sizeof(click_ip));

    click_udp *udph = (click_udp *)(p->data() + sizeof(click_ip));
    int ulen = ber.length() + sizeof(click_udp);
    udph->uh_sport = htons(_sport);
    udph->uh_dport = htons(_dport);
    udph->uh_ulen = htons(ulen);
    udph->uh_sum = 0;

    memcpy(udph + 1, ber.data(), ber.length());
    
    unsigned csum = ~click_in_cksum((unsigned char *)udph, ulen) & 0xFFFF;
#ifdef __KERNEL__
    udph->uh_sum = csum_tcpudp_magic(_src.addr(), _dst.addr(),
				     ulen, IP_PROTO_UDP, csum);
#else
    unsigned short *words = (unsigned short *)&iph->ip_src;
    csum += words[0];
    csum += words[1];
    csum += words[2];
    csum += words[3];
    csum += htons(IP_PROTO_UDP);
    csum += htons(ulen);
    while (csum >> 16)
      csum = (csum & 0xFFFF) + (csum >> 16);
    udph->uh_sum = ~csum & 0xFFFF;
#endif
    
  } else
    memcpy(p->data(), ber.data(), ber.length());

  // enqueue packet on Queue; drop packets at head
  int next = next_i(_tail);
  if (next == _head) {
    _drops++;
    p->kill();
  } else {
    _queue[_tail] = p;
    _tail = next;
    _task.reschedule();
  }

  return 0;
}

bool
SNMPTrapSource::run_task(Task *)
{
  // see NOTE above
  while (_head != _tail) {
    int next = next_i(_head);
    output(0).push(_queue[_head]);
    _head = next;
  }
  return true;
}

static int
trap_write_handler(const String &, Element *e, void *thunk, ErrorHandler *errh)
{
  SNMPTrapSource *ts = (SNMPTrapSource *)e;
  int which = (int)thunk;

  int result = ts->generate_trap(which);
  if (result == -ENOMEM)
    errh->error("out of memory");
  else if (result < 0)
    errh->error("error %d while generating trap", -result);
  return result;
}

String
SNMPTrapSource::read_handler(Element *e, void *thunk)
{
  SNMPTrapSource *ts = (SNMPTrapSource *)e;
  switch ((int)thunk) {
   case H_drops:	return String(ts->_drops.value());
   case H_enterprise:	return cp_unparse_snmp_oid(ts->_enterprise);
   case H_src:		return ts->_src.unparse();
   case H_dst:		return ts->_dst.unparse();
   case H_sport:	return String(ts->_sport);
   case H_dport:	return String(ts->_dport);
   case H_active: 	return cp_unparse_bool(ts->_active);

   case H_traps: {
     StringAccum sa;
     for (int i = 0; i < ts->_names.size(); i++)
       sa << ts->_names[i] << '\n';
     return sa.take_string();
   }
   
   default:	return "<error>";
  }
}

int
SNMPTrapSource::write_handler(const String &str_in, Element *e, void *thunk, ErrorHandler *errh)
{
  SNMPTrapSource *ts = (SNMPTrapSource *)e;
  String str = cp_uncomment(str_in);
  switch ((int)thunk) {

   case H_src:
   case H_dst: {
     IPAddress a;
     if (!cp_ip_address(str, &a, e))
       return errh->error("expected IP address");
     ((int)thunk == H_src ? ts->_src = a : ts->_dst = a);
     return 0;
   }
   
   case H_sport:
   case H_dport: {
     int x;
     if (!cp_integer(str, &x) || x < 0 || x > 0xFFFF)
       return errh->error("expected port number");
     ((int)thunk == H_sport ? ts->_sport = x : ts->_dport = x);
     return 0;
   }
   
   case H_active: {
     bool x;
     if (!cp_bool(str, &x))
       return errh->error("expected boolean value");
     ts->_active = x;
     return 0;
   }
   
   default:
    return -EINVAL;
    
  }
}

void
SNMPTrapSource::add_handlers()
{
  add_read_handler("drops", read_handler, (void *)H_drops);
  add_read_handler("enterprise", read_handler, (void *)H_enterprise);
  add_read_handler("src", read_handler, (void *)H_src);
  add_write_handler("src", write_handler, (void *)H_src);
  add_read_handler("dst", read_handler, (void *)H_dst);
  add_write_handler("dst", write_handler, (void *)H_dst);
  add_read_handler("sport", read_handler, (void *)H_sport);
  add_write_handler("sport", write_handler, (void *)H_sport);
  add_read_handler("dport", read_handler, (void *)H_dport);
  add_write_handler("dport", write_handler, (void *)H_dport);
  add_read_handler("traps", read_handler, (void *)H_traps);
  add_write_handler("active", write_handler, (void *)H_active, Handler::CHECKBOX);
  add_read_handler("active", read_handler, (void *)H_active);

  for (int i = 0; i < _names.size(); i++)
      add_write_handler("send_" + _names[i], trap_write_handler, (void *)i, Handler::BUTTON);
}

ELEMENT_REQUIRES(SNMPBasics SNMPBER SNMPVariableInfo)
EXPORT_ELEMENT(SNMPTrapSource)
