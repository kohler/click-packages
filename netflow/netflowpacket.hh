// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowpacket.{cc,hh} -- parses Netflow V1, V5, V7, V9, and IPFIX
// packets
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#ifndef NETFLOWPACKET_HH
#define NETFLOWPACKET_HH
#include <click/packet.hh>
#include <click/straccum.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <click/string.hh>
#include <click/error.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/ip6address.hh>
#include <clicknet/ip.h>
#include <clicknet/ip6.h>
#include <clicknet/udp.h>
#include <click/glue.hh>
#include "netflowdata.hh"
#include "ipfixtypes.hh"
#include "netflowtemplatecache.hh"
CLICK_DECLS

class NetflowPacket {

public:

  struct V1_Header {
    uint16_t version;		/* Export format version number */
    uint16_t count;		/* Number of flows exported */
    uint32_t uptime;		/* Millisec since router was last booted */
    uint32_t unix_secs;		/* Seconds in Unix time */
    uint32_t unix_nsecs;	/* Residual nanosecs in Unix time */
  };

  struct V5_Header {
    uint16_t version;		/* Export format version number */
    uint16_t count;		/* Number of flows exported */
    uint32_t uptime;		/* Millisec since router was last booted */
    uint32_t unix_secs;		/* Seconds in Unix time */
    uint32_t unix_nsecs;	/* Residual nanosecs in Unix time */
    uint32_t flow_sequence;	/* Sequence counter of total flows seen */
    uint8_t engine_type;	/* Type of flow switching engine */
    uint8_t engine_id;		/* ID number of flow switching engine */
    uint16_t sampling;		/* Sampling mode and interval */
  };

  struct V7_Header {
    uint16_t version;           /* Export format version number */
    uint16_t count;             /* Number of flows exported */
    uint32_t uptime;            /* Millisec since router was last booted */
    uint32_t unix_secs;         /* Seconds in Unix time */
    uint32_t unix_nsecs;        /* Residual nanosecs in Unix time */
    uint32_t flow_sequence;     /* Sequence counter of total flows seen */
    uint32_t reserved;
  };

  struct V9_Header {
    uint16_t version;		/* Export format version number */
    uint16_t count;		/* Number of flows exported */
    uint32_t uptime;		/* Millisec since router was last booted */
    uint32_t unix_secs;		/* Seconds in Unix time */
    uint32_t flow_sequence;	/* Sequence counter of total flows seen */
    uint32_t source_id;		/* Equivalent of engine_type and engine_id */
  };

  struct IPFIX_Header {
    uint16_t version;		/* Export format version number */
    uint16_t length;		/* Total length in bytes including header */
    uint32_t unix_secs;		/* Seconds in Unix time */
    uint32_t flow_sequence;	/* Sequence counter of total flows seen */
    uint32_t source_id;		/* Equivalent of engine_type and engine_id */
  };

  struct V1_Record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;		/* IP address of next hop router */
    uint16_t input;		/* SNMP id of input interface */
    uint16_t output;		/* SNMP id of output interface */
    uint32_t dpkts;		/* Packets in the flow */
    uint32_t doctets;		/* Octets in the flow */
    uint32_t first;		/* Uptime at start of flow */
    uint32_t last;		/* Uptime at receipt of last packet of flow */
    uint16_t sport;		/* Transport layer source port */
    uint16_t dport;		/* Transport layer destination port */
    uint16_t pad1;
    uint8_t prot;		/* IP protocol */
    uint8_t tos;		/* IP TOS */
    uint8_t flags;		/* Cumulative OR of TCP flags */
    uint8_t tcp_retx_cnt;
    uint8_t tcp_retx_secs;
    uint8_t tcp_misseq_cnt;
    uint32_t reserved;
  };

  struct V5_Record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;		/* IP address of next hop router */
    uint16_t input;		/* SNMP id of input interface */
    uint16_t output;		/* SNMP id of output interface */
    uint32_t dpkts;		/* Packets in the flow */
    uint32_t doctets;		/* Octets in the flow */
    uint32_t first;		/* Uptime at start of flow */
    uint32_t last;		/* Uptime at receipt of last packet of flow */
    uint16_t sport;		/* Transport layer source port */
    uint16_t dport;		/* Transport layer destination port */
    uint8_t pad1;
    uint8_t flags;		/* Cumulative OR of TCP flags */
    uint8_t prot;		/* IP protocol */
    uint8_t tos;		/* IP TOS */
    uint16_t src_as;		/* AS of source address (origin or peer) */
    uint16_t dst_as;		/* AS of dest address (origin or peer) */
    uint8_t src_mask;		/* Source address prefix mask bits */
    uint8_t dst_mask;		/* Dest address prefix mask bits */
    uint16_t reserved;
  };

  struct V7_Record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;		/* IP address of next hop router */
    uint16_t input;		/* SNMP id of input interface */
    uint16_t output;		/* SNMP id of output interface */
    uint32_t dpkts;		/* Packets in the flow */
    uint32_t doctets;		/* Octets in the flow */
    uint32_t first;		/* Uptime at start of flow */
    uint32_t last;		/* Uptime at receipt of last packet of flow */
    uint16_t sport;		/* Transport layer source port */
    uint16_t dport;		/* Transport layer destination port */
    uint8_t sc_flags;           /* Shortcut mode (dst only, src only, full) */
    uint8_t flags;              /* Cumulative OR of TCP flags */
    uint8_t prot;               /* IP protocol */
    uint8_t tos;		/* IP TOS */
    uint16_t src_as;		/* AS of source address (origin or peer) */
    uint16_t dst_as;		/* AS of dest address (origin or peer) */
    uint8_t src_mask;		/* Source address prefix mask bits */
    uint8_t dst_mask;		/* Dest address prefix mask bits */
    uint16_t pad;
    uint32_t router_sc;         /* Router which is shortcut by switch */
  };

  struct V9_Flowset {
    uint16_t id;		/* Distinguishes template records from data records */
    uint16_t length;		/* Total length of this flowset in bytes */
  };

  struct V9_Template {
    uint16_t id;		/* ID of this template record */
    uint16_t count;		/* Number of fields in this template record */
  };

  struct V9_Template_Field {
    uint16_t type;		/* Field type (see below) */
    uint16_t length;		/* Length in bytes of field value */
  };

  struct IPFIX_Template_Field {
    uint16_t type;		/* Field type. 1-127 are V9, >=32768 are custom. */
    uint16_t length;		/* Length in bytes of field value, 65535 means variable length */
    uint32_t enterprise;	/* Enterprise number for custom types */
  };

  NetflowPacket(const Packet *p) : _p(p) {}
  virtual ~NetflowPacket() { }
  static NetflowPacket *netflow_packet(const Packet *p, NetflowTemplateCache *template_cache);
  static NetflowPacket *netflow_packet(const Packet *p);

  IPAddress srcaddr() const;

  virtual unsigned short version() const = 0;
  virtual unsigned short count() const = 0;
  virtual unsigned long uptime() const = 0;
  virtual unsigned long unix_secs() const = 0;
  virtual unsigned long unix_nsecs() const = 0;

  virtual IPAddress srcaddr(int) const = 0;
  virtual IPAddress dstaddr(int) const = 0;
  virtual unsigned short input(int) const = 0;
  virtual unsigned short output(int) const = 0;
  virtual unsigned long dpkts(int) const = 0;
  virtual unsigned long doctets(int) const = 0;
  virtual unsigned long first(int) const = 0;
  virtual unsigned long last(int) const = 0;
  virtual unsigned short sport(int i) const = 0;
  virtual unsigned short dport(int i) const = 0;
  virtual unsigned char prot(int i) const = 0;
  virtual unsigned char tos(int i) const = 0;
  virtual unsigned char flags(int i) const = 0;

  virtual String unparse(bool verbose) const;
  virtual String unparse_record(int i, String tag, bool verbose) const;

protected:

  const Packet *_p;
};

// Netflow V1, V5, V7

template<class Header, class Record>
class NetflowVersionPacket : public NetflowPacket {

public:
  NetflowVersionPacket(const Packet *p, Header *h, unsigned len);
  virtual ~NetflowVersionPacket() { }

  virtual unsigned short version() const { return ntohs(_h->version); }
  virtual unsigned short count() const { return ntohs(_h->count); }
  virtual unsigned long uptime() const { return ntohl(_h->uptime); }
  virtual unsigned long unix_secs() const { return ntohl(_h->unix_secs); }
  virtual unsigned long unix_nsecs() const { return ntohl(_h->unix_nsecs); }

  virtual IPAddress srcaddr(int i) const { return _r[i].srcaddr; }
  virtual IPAddress dstaddr(int i) const { return _r[i].dstaddr; }
  virtual unsigned short input(int i) const { return ntohs(_r[i].input); }
  virtual unsigned short output(int i) const { return ntohs(_r[i].output); }
  virtual unsigned long dpkts(int i) const { return ntohl(_r[i].dpkts); }
  virtual unsigned long doctets(int i) const { return ntohl(_r[i].doctets); }
  virtual unsigned long first(int) const;
  virtual unsigned long last(int) const;
  virtual unsigned short sport(int i) const { return ntohs(_r[i].sport); }
  virtual unsigned short dport(int i) const { return ntohs(_r[i].dport); }
  virtual unsigned char prot(int i) const { return _r[i].prot; }
  virtual unsigned char tos(int i) const { return _r[i].tos; }
  virtual unsigned char flags(int i) const { return _r[i].flags; }

private:

  Header *_h;
  Record *_r;
};

inline IPAddress
NetflowPacket::srcaddr() const
{
  const click_ip *iph = _p->ip_header();
  return iph ? IPAddress(iph->ip_src) : IPAddress(0);
}

template<class Header, class Record> inline unsigned long
NetflowVersionPacket<Header, Record>::first(int i) const
{
  return unix_secs() + (int)(ntohl(_r[i].first) - uptime()) / 1000;
}

template<class Header, class Record> inline unsigned long
NetflowVersionPacket<Header, Record>::last(int i) const
{
  return unix_secs() + (int)(ntohl(_r[i].last) - uptime()) / 1000;
}

template<class Header, class Record> inline
NetflowVersionPacket<Header, Record>::NetflowVersionPacket(const Packet *p, Header *h, unsigned len)
  : NetflowPacket(p), _h(h)
{
  _r = (Record *)(_h + 1);
  len -= sizeof(Header);
  if (sizeof(Record)*count() > len)
    _h->count = htons(len/sizeof(Record));
}

// NetFlow V9 and IPFIX

struct Netflow_Field_Key {
  uint32_t enterprise;
  uint16_t type;
};

inline bool
operator==(const Netflow_Field_Key &a, const Netflow_Field_Key &b)
{
  return a.enterprise == b.enterprise && a.type == b.type;
}

inline unsigned
hashcode(Netflow_Field_Key a)
{
  return a.type;
}

typedef HashMap<Netflow_Field_Key, NetflowData>::const_iterator NetflowDataIterator;

class NetflowDataRecord : public HashMap<Netflow_Field_Key, NetflowData> {

public:

  NetflowDataRecord() { }

  bool insert(const NetflowData &data) {
    const Netflow_Field_Key key = { data.enterprise(), data.type() };
    return HashMap<Netflow_Field_Key, NetflowData>::insert(key, data);
  }
  NetflowData *findp(uint32_t enterprise, const uint16_t type) const {
    const Netflow_Field_Key key = { enterprise, type };
    return HashMap<Netflow_Field_Key, NetflowData>::findp(key);
  }

  // These functions exist solely for compatibility with
  // NetflowPacket and return 0 (or a 0 representation) if the field
  // was not found or parsed from the template definition.
  IPAddress srcaddr() const { return ipaddress(0, IPFIX_sourceIPv4Address); }
  IPAddress dstaddr() const { return ipaddress(0, IPFIX_destinationIPv4Address); }
#if HAVE_IP6
  IP6Address srcaddr6() const { return ip6address(0, IPFIX_sourceIPv4Address); }
  IP6Address dstaddr6() const { return ip6address(0, IPFIX_destinationIPv6Address); }
#endif
  unsigned short input() const { return value<unsigned short>(0, IPFIX_ingressInterface); }
  unsigned short output() const { return value<unsigned short>(0, IPFIX_egressInterface); }
  unsigned long dpkts() const { return value<unsigned long>(0, IPFIX_packetDeltaCount); }
  unsigned long doctets() const { return value<unsigned long>(0, IPFIX_octetDeltaCount); }
  unsigned long first() const { return value<unsigned long>(0, IPFIX_flowStartSysUpTime); }
  unsigned long last() const { return value<unsigned long>(0, IPFIX_flowEndSysUpTime); }
  unsigned short sport() const { return value<unsigned short>(0, IPFIX_sourceTransportPort); }
  unsigned short dport() const { return value<unsigned short>(0, IPFIX_destinationTransportPort); }
  unsigned char prot() const { return value<unsigned char>(0, IPFIX_protocolIdentifier); }
  unsigned char tos() const { return value<unsigned char>(0, IPFIX_classOfServiceIPv4); }
  unsigned char flags() const { return value<unsigned char>(0, IPFIX_tcpControlBits); }

  IPAddress ipaddress(uint32_t enterprise, uint16_t type) const {
    NetflowData *data = findp(enterprise, type);
    return (data && data->parsed()) ? data->ipaddress() : IPAddress(0);
  }
#if HAVE_IP6
  IP6Address ip6address(uint32_t enterprise, uint16_t type) const {
    NetflowData *data = findp(enterprise, type);
    return (data && data->parsed()) ? data->ip6address() : IP6Address(0);
  }
#endif
  template<class T> T value(uint32_t enterprise, uint16_t type) const {
    NetflowData *data = findp(enterprise, type);
    return (data && data->parsed()) ? data->value<T>() : (T)0;
  }
};

template<class Header, class Template_Field>
class NetflowTemplatePacket : public NetflowPacket {

public:
  NetflowTemplatePacket<Header, Template_Field>(const Packet *p, Header *h, unsigned len, NetflowTemplateCache *template_cache);

  virtual unsigned short version() const { return ntohs(_h->version); }
  virtual unsigned short count() const { return _r.size(); }
  virtual unsigned long uptime() const;
  virtual unsigned long unix_secs() const { return ntohl(_h->unix_secs); }
  // Neither Netflow V9 nor IPFIX headers have a nanoseconds field
  virtual unsigned long unix_nsecs() const { return 0; }

  // These functions exist solely for compatibility with NetflowPacket
  // and return 0 (or a 0 representation) if the field was not found
  // or parsed from the template definition.
  virtual IPAddress srcaddr(int i) const { return _r[i].srcaddr(); }
  virtual IPAddress dstaddr(int i) const { return _r[i].dstaddr(); }
  virtual unsigned short input(int i) const { return _r[i].input(); }
  virtual unsigned short output(int i) const { return _r[i].output(); }
  virtual unsigned long dpkts(int i) const { return _r[i].dpkts(); }
  virtual unsigned long doctets(int i) const { return _r[i].doctets(); }
  virtual unsigned long first(int i) const;
  virtual unsigned long last(int i) const;
  virtual unsigned short sport(int i) const { return _r[i].sport(); }
  virtual unsigned short dport(int i) const { return _r[i].dport(); }
  virtual unsigned char prot(int i) const { return _r[i].prot(); }
  virtual unsigned char tos(int i) const { return _r[i].tos(); }
  virtual unsigned char flags(int i) const { return _r[i].flags(); }

  virtual String unparse_record(int i, String tag, bool verbose) const;

private:
  Header *_h;
  Vector<NetflowDataRecord> _r;
  NetflowTemplateCache *_template_cache;
};

typedef NetflowTemplatePacket<NetflowPacket::V9_Header, NetflowPacket::V9_Template_Field> NetflowVersion9Packet;

typedef NetflowTemplatePacket<NetflowPacket::IPFIX_Header, NetflowPacket::IPFIX_Template_Field> IPFIXPacket;

inline NetflowPacket *
NetflowPacket::netflow_packet(const Packet *p, NetflowTemplateCache *template_cache)
{
  V1_Header *h;
  unsigned len = p->length() - p->network_header_offset();

  // For backward compatibility with previous versions of this parser,
  // support parsing raw UDP packets.
  const click_ip *iph = p->ip_header();
  if (iph && iph->ip_p == IP_PROTO_UDP) {
    if (len < (sizeof(click_ip) + sizeof(click_udp)))
      return 0;
    len -= sizeof(click_ip) + sizeof(click_udp);
    const click_udp *udph = (const click_udp *)p->transport_header();
    h = (V1_Header *)&udph[1];
  } else {
    h = (V1_Header *)p->data();
  }

  // All known headers are at least the size of V1_Header
  if (len < sizeof(V1_Header))
    return 0;

  switch (ntohs(h->version)) {
  case 1:
    return new NetflowVersionPacket<V1_Header, V1_Record>(p, h, len);
  case 5:
    if (len >= sizeof(V5_Header))
      return new NetflowVersionPacket<V5_Header, V5_Record>(p, (V5_Header *)h, len);
    break;
  case 7:
    if (len >= sizeof(V7_Header))
      return new NetflowVersionPacket<V7_Header, V7_Record>(p, (V7_Header *)h, len);
    break;
  case 9:
    if (len >= sizeof(V9_Header))
      return new NetflowVersion9Packet(p, (V9_Header *)h, len, template_cache);
    break;
  case 10:
    if (len >= sizeof(IPFIX_Header) && ntohs(((IPFIX_Header*)h)->length) < len)
      len = ntohs(((IPFIX_Header*)h)->length);
    if (len >= sizeof(IPFIX_Header))
      return new IPFIXPacket(p, (IPFIX_Header *)h, len, template_cache);
    break;
  }

  return 0;
}

inline NetflowPacket *
NetflowPacket::netflow_packet(const Packet *p)
{
  return NetflowPacket::netflow_packet(p, 0);
}

CLICK_ENDDECLS
#endif
