// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowexport.{cc,hh} -- element generates Cisco NetFlow packets
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "netflowexport.hh"

CLICK_DECLS

NetflowExport::NetflowExport()
  : _flow_sequence(0), _timer(this)
{
}

NetflowExport::~NetflowExport()
{
}

int
NetflowExport::configure(Vector<String> &conf, ErrorHandler *errh)
{
  Element *e = 0;
  _version = 9;
  _source_id = click_random(0, 65535);
  _template_id = 1025;
  _debug = false;
  _interval = 0;

  if (cp_va_kparse(conf, this, errh,
		   "NOTIFIER", cpkP+cpkM, cpElement, &e,
		   "VERSION", 0, cpUnsignedShort, &_version,
		   "SOURCE_ID", 0, cpUnsigned, &_source_id,
		   "TEMPLATE_ID", 0, cpUnsignedShort, &_template_id,
		   "DEBUG", 0, cpBool, &_debug,
		   "INTERVAL", 0, cpSecondsAsMilli, &_interval,
		   cpEnd) < 0)
    return -1;

  if (e && !(_agg_notifier = (AggregateNotifier *)e->cast("AggregateNotifier")))
    return errh->error("%s is not an AggregateNotifier", e->name().c_str());

  switch (_version) {
  case 1:
  case 5:
  case 7:
  case 9:
  case 10: // IPFIX
    break;
  default:
    return errh->error("unsupported Netflow version %d", _version);
  }

  if (_template_id < 256)
    return errh->error("template identifier must be greater than 255");

  if (e && !(_agg_notifier = (AggregateNotifier *)e->cast("AggregateNotifier")))
    return errh->error("%s is not an AggregateNotifier", e->name().c_str());

  return 0;
}

int
NetflowExport::initialize(ErrorHandler *)
{
  // Keep track of exporter uptime
  _start = Timestamp::now();
  _agg_notifier->add_listener(this);
  if (_interval) {
    _timer.initialize(this);
    _timer.schedule_after_msec(_interval);
  }
  return 0;
}

NetflowExport::Flow::Flow(const Packet *p, NetflowExport *exporter, unsigned flow_sequence)
  : NetflowDataRecord(),
    _flow_sequence(flow_sequence),
    _agg(AGGREGATE_ANNO(p)), _start(Timestamp::now()),
    _packets(1), _bytes(p->network_length())
{
  const click_ether *eth = p->ether_header();
  if (eth) {
    insert(NetflowData(0, IPFIX_sourceMacAddress, eth->ether_dhost, 6));
    insert(NetflowData(0, IPFIX_destinationMacAddress, eth->ether_dhost, 6));
  }

  const click_ip *iph = p->ip_header();
  if (iph) {
    insert(NetflowData(0, IPFIX_protocolIdentifier, &iph->ip_p, 1));
    insert(NetflowData(0, IPFIX_classOfServiceIPv4, &iph->ip_tos, 1));
    insert(NetflowData(0, IPFIX_sourceIPv4Address, &iph->ip_src, 4));
    insert(NetflowData(0, IPFIX_destinationIPv4Address, &iph->ip_dst, 4));

    if (iph->ip_p == IP_PROTO_UDP) {
      const click_udp *udph = (const click_udp *)p->transport_header();
      insert(NetflowData(0, IPFIX_sourceTransportPort, &udph->uh_sport, 2));
      insert(NetflowData(0, IPFIX_destinationTransportPort, &udph->uh_dport, 2));
      if (exporter->version() == 10) {
	insert(NetflowData(0, IPFIX_udpSourcePort, &udph->uh_sport, 2));
	insert(NetflowData(0, IPFIX_udpDestinationPort, &udph->uh_dport, 2));
      }
    } else if (iph->ip_p == IP_PROTO_TCP) {
      const click_tcp *tcph = (const click_tcp *)p->transport_header();
      insert(NetflowData(0, IPFIX_sourceTransportPort, &tcph->th_sport, 2));
      insert(NetflowData(0, IPFIX_destinationTransportPort, &tcph->th_dport, 2));
      if (exporter->version() == 10) {
	insert(NetflowData(0, IPFIX_tcpSourcePort, &tcph->th_sport, 2));
	insert(NetflowData(0, IPFIX_tcpDestinationPort, &tcph->th_dport, 2));
      }
      insert(NetflowData(0, IPFIX_tcpControlBits, &tcph->th_flags, 1));
    }

    if (p->dst_ip_anno()) {
      insert(NetflowData(0, IPFIX_ipNextHopIPv4Address, p->dst_ip_anno().data(), 4));
    }
  }
}

#define ARRAYSIZE(a) (sizeof((a))/sizeof((a)[0]))
#define ROUNDUP(n, multiple_of) (((n)+((multiple_of)-1))/(multiple_of)*(multiple_of))

// Good for V1, V5, and V7
template <class Header, class Record> void
NetflowExport::Flow::fill_record(NetflowExport *exporter, Record *r, Timestamp &now)
{
  memset(r, 0, sizeof(*r));
  r->dpkts = htonl((uint32_t)_packets);
  r->doctets = htonl((uint32_t)_bytes);
  r->first = htonl(_start.sec() - exporter->start());
  r->last = htonl(now.sec() - exporter->start());

  struct {
    uint16_t type;
    uint8_t *dst;
  } v1_fields[] = {
    { IPFIX_sourceIPv4Address, (uint8_t *)&r->srcaddr },
    { IPFIX_destinationIPv4Address, (uint8_t *)&r->dstaddr },
    { IPFIX_ipNextHopIPv4Address, (uint8_t *)&r->nexthop },
    { IPFIX_sourceTransportPort, (uint8_t *)&r->sport },
    { IPFIX_destinationTransportPort, (uint8_t *)&r->dport },
    { IPFIX_protocolIdentifier, (uint8_t *)&r->prot },
    { IPFIX_classOfServiceIPv4, (uint8_t *)&r->tos },
    { IPFIX_tcpControlBits, (uint8_t *)&r->flags },
  };
    
  for (unsigned i = 0; i < ARRAYSIZE(v1_fields); i++) {
    const NetflowData *data = findp(0, v1_fields[i].type);
    if (data) {
      // Assert that everything we added in the ctor was parsed
      assert(data->data() && data->parsed() &&
	     data->length() < (unsigned)((uint8_t *)&r[1] - v1_fields[i].dst));
      memcpy(v1_fields[i].dst, data->data(), data->length());
    }
  }
}

void NetflowExport::Flow::send(NetflowExport *exporter)
{
  Timestamp now = Timestamp::now(); 
  unsigned length = 0, template_length = 0, data_length = 0;

  switch (exporter->version()) {

  case 1:
    length += sizeof(NetflowPacket::V1_Header) + sizeof(NetflowPacket::V1_Record);
    break;

  case 5:
    length += sizeof(NetflowPacket::V5_Header) + sizeof(NetflowPacket::V5_Record);
    break;

  case 7:
    length += sizeof(NetflowPacket::V7_Header) + sizeof(NetflowPacket::V7_Record);
    break;

  case 9:
  case 10:
    // Convert to uptime for V9
    uint32_t start = htonl(exporter->version() == 9 ?
			   (_start.sec() - exporter->start()) :
			   _start.sec());
    uint32_t end = htonl(exporter->version() == 9 ?
			 (now.sec() - exporter->start()) :
			 now.sec());
    if (exporter->version() == 9) {
      length += sizeof(NetflowPacket::V9_Header);
      insert(NetflowData(0, IPFIX_flowStartSysUpTime, &start, 4));
      insert(NetflowData(0, IPFIX_flowEndSysUpTime, &end, 4));
    } else {
      length += sizeof(NetflowPacket::IPFIX_Header);
      insert(NetflowData(0, IPFIX_flowStartSeconds, &start, 4));
      insert(NetflowData(0, IPFIX_flowEndSeconds, &end, 4));
    }

    // Add counters
    netflow_count_t packets = unaligned_ntoh<netflow_count_t>(&_packets);
    netflow_count_t bytes = unaligned_ntoh<netflow_count_t>(&_bytes);
    insert(NetflowData(0, IPFIX_packetDeltaCount, &packets, sizeof(packets)));
    insert(NetflowData(0, IPFIX_octetDeltaCount, &bytes, sizeof(bytes)));

    // Template flowset length
    template_length = sizeof(NetflowPacket::V9_Flowset) + sizeof(NetflowPacket::V9_Template);

    // Data flowset length
    data_length = sizeof(NetflowPacket::V9_Flowset);

    for (NetflowDataIterator iter = begin(); iter.live(); iter++) {
      NetflowData data = iter.value();
      // Template field
      template_length += sizeof(NetflowPacket::V9_Template_Field);
      // Corresponding data field
      data_length += data.length();
    }

    // Align the end of both flowsets on 32-bit boundaries
    template_length = ROUNDUP(template_length, 4);
    data_length = ROUNDUP(data_length, 4);

    length += template_length + data_length;
    break;
  }

  // Reserve some headroom for UDP headers. UDP is the transport for
  // V9, and the most common transport for IPFIX.
  unsigned headroom = Packet::DEFAULT_HEADROOM + sizeof(click_ip) + sizeof(click_udp);
  WritablePacket *np = Packet::make(headroom, 0, length, 0);

  switch (exporter->version()) {

  case 1: {
    NetflowPacket::V1_Header *h = (NetflowPacket::V1_Header *)np->data();
    memset(h, 0, sizeof(*h));
    h->version = htons(exporter->version());
    h->count = htons(1); // TODO: Batch flows
    h->uptime = htonl(now.sec() - _start.sec());
    h->unix_secs = htonl(now.sec());
    h->unix_nsecs = htonl(now.nsec());

    NetflowPacket::V1_Record *r = (NetflowPacket::V1_Record *)&h[1];
    fill_record<NetflowPacket::V1_Header, NetflowPacket::V1_Record>(exporter, r, now);

    break;
  }

  case 5: {
    NetflowPacket::V5_Header *h = (NetflowPacket::V5_Header *)np->data();
    memset(h, 0, sizeof(*h));
    h->version = htons(exporter->version());
    h->count = htons(1); // TODO: Batch flows
    h->uptime = htonl(now.sec() - _start.sec());
    h->unix_secs = htonl(now.sec());
    h->unix_nsecs = htonl(now.nsec());
    h->flow_sequence = htonl(_flow_sequence);
    h->engine_type = (uint8_t)((exporter->source_id() >> 8) & 0xff);
    h->engine_id = (uint8_t)(exporter->source_id() & 0xff);

    NetflowPacket::V5_Record *r = (NetflowPacket::V5_Record *)&h[1];
    fill_record<NetflowPacket::V5_Header, NetflowPacket::V5_Record>(exporter, r, now);

    break;
  }

  case 7: {
    NetflowPacket::V7_Header *h = (NetflowPacket::V7_Header *)np->data();
    memset(h, 0, sizeof(*h));
    h->version = htons(exporter->version());
    h->count = htons(1); // TODO: Batch flows
    h->uptime = htonl(now.sec() - _start.sec());
    h->unix_secs = htonl(now.sec());
    h->unix_nsecs = htonl(now.nsec());
    h->flow_sequence = htonl(_flow_sequence);

    NetflowPacket::V7_Record *r = (NetflowPacket::V7_Record *)&h[1];
    fill_record<NetflowPacket::V7_Header, NetflowPacket::V7_Record>(exporter, r, now);

    break;
  }

  case 9:
  case 10: {
    NetflowPacket::V9_Flowset *flowset;

    if (exporter->version() == 9) {
      NetflowPacket::V9_Header *h = (NetflowPacket::V9_Header *)np->data();
      h->version = htons(exporter->version());
      h->count = htons(2); // TODO: Batch flows
      h->uptime = htonl(now.sec() - exporter->start());
      h->unix_secs = htonl(now.sec());
      h->flow_sequence = htonl(_flow_sequence);
      h->source_id = htonl(exporter->source_id());
      // Template flowset header
      flowset = (NetflowPacket::V9_Flowset *)&h[1];
      flowset->id = htons(0);
    } else {
      NetflowPacket::IPFIX_Header *h = (NetflowPacket::IPFIX_Header *)np->data();
      h->version = htons(exporter->version());
      h->length = htonl(np->length());
      h->unix_secs = htonl(now.sec());
      h->flow_sequence = htonl(_flow_sequence);
      h->source_id = htonl(exporter->source_id());
      // Template flowset header
      flowset = (NetflowPacket::V9_Flowset *)&h[1];
      flowset->id = htons(2);
    }
    flowset->length = htons(template_length);

    // Template header
    NetflowPacket::V9_Template *templp = (NetflowPacket::V9_Template *)&flowset[1];
    templp->id = htons(exporter->template_id() + _agg);
    templp->count = htons(size());

    // Template fields
    NetflowPacket::V9_Template_Field *field = (NetflowPacket::V9_Template_Field *)&templp[1];
    for (NetflowDataIterator iter = begin(); iter.live(); iter++, field++) {
      NetflowData data = iter.value();
      field->type = htons(data.type());
      field->length = htons(data.length());
    }

    // Data flowset header
    flowset = (NetflowPacket::V9_Flowset *)((intptr_t)flowset + template_length);
    flowset->id = htons(exporter->template_id() + _agg);
    flowset->length = htons(data_length);

    // Data fields
    unsigned char *data_field = (unsigned char *)&flowset[1];
    for (NetflowDataIterator iter = begin(); iter.live(); iter++) {
      NetflowData data = iter.value();
      // Assert that everything we added in the ctor was parsed
      assert(data.data() && data.parsed() &&
	     data.length() < (unsigned)(np->end_data() - data_field));
      memcpy(data_field, data.data(), data.length());
      data_field += data.length();
    }

    break;
  }
  }

  exporter->output(0).push(np);
  _packets = _bytes = 0;
}

void
NetflowExport::aggregate_notify(uint32_t agg, AggregateEvent event, const Packet *p)
{
  switch (event) {

  case NEW_AGG:
    _flows.set(agg, new Flow(p, this, _flow_sequence++));
    // Fall through to immediately generating a flow record for new
    // flows if debugging.
    if (!_debug)
      break;

  case DELETE_AGG: {
    if (HashTable<uint32_t, Flow *>::iterator it = _flows.find(agg)) { 
      Flow *flow = it.value();
      _flows.erase(it);
      flow->send(this);
      delete flow;
    }
    break;
  }
  }
}

Packet *
NetflowExport::simple_action(Packet *p)
{
  Flow *flow = _flows.get(AGGREGATE_ANNO(p));
  if (flow)
    flow->handle_packet(p);
  p->kill();
  return 0;
}

void
NetflowExport::run_timer(Timer *)
{
  for (HashTable<uint32_t, Flow *>::iterator i = _flows.begin();
       i != _flows.end();
       ++i)
    if (i.value())
      i.value()->send(this);
  _timer.reschedule_after_msec(_interval);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel AggregateNotifier NetflowPacket)
EXPORT_ELEMENT(NetflowExport)
