// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowtemplatecache.{cc,hh} -- caches Netflow V9/IPFIX templates
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#ifndef NETFLOWTEMPLATECACHE_HH
#define NETFLOWTEMPLATECACHE_HH
#include <click/element.hh>
#include <click/hashmap.hh>
#include "netflowtemplate.hh"
CLICK_DECLS

/*
=c

NetflowTemplateCache([TAG, KEYWORDS])

=s Mazu Logging

caches Netflow V9/IPFIX template records

=io

None

=d

Caches Netflow V9/IPFIX template records so that templated packets can
be parsed. Specify this element as a keyword to Netflow parsing
elements such as NetflowPrint if you want to be able to parse Netflow
V9/IPFIX data records.

=a

NetflowPrint */

// Netflow V9 spec says: "Collector devices should use the combination
// of the source IP address plus the Source ID field to associate an
// incoming NetFlow export packet with a unique instance of NetFlow on
// a particular device."
struct Netflow_Template_Key {
  IPAddress srcaddr;		// Source IP address of the NetflowPacket
  uint32_t source_id;		// Source ID from the V9_Header
  uint16_t template_id;		// Template ID from the V9_Template header
};

class NetflowTemplateCache : public Element  { 

public:
  NetflowTemplateCache() { }

  bool insert(IPAddress srcaddr, uint32_t source_id, uint16_t template_id, const NetflowTemplate &templ) {
    const Netflow_Template_Key key = { srcaddr, source_id, template_id };
    return _t.insert(key, templ);
  }
  NetflowTemplate *findp(IPAddress srcaddr, uint32_t source_id, uint16_t template_id) const {
    const Netflow_Template_Key key = { srcaddr, source_id, template_id };
    return _t.findp(key);
  }
  bool remove(IPAddress srcaddr, uint32_t source_id, uint16_t template_id);
  bool remove(IPAddress srcaddr, uint32_t source_id);
  
  const char *class_name() const	{ return "NetflowTemplateCache"; }

 private:

  typedef HashMap<Netflow_Template_Key, NetflowTemplate> Table;
  HashMap<Netflow_Template_Key, NetflowTemplate> _t;
  
};

inline bool
operator==(const Netflow_Template_Key &a, const Netflow_Template_Key &b)
{
  return a.srcaddr == b.srcaddr && a.source_id == b.source_id
    && a.template_id == b.template_id;
}

inline unsigned
hashcode(const Netflow_Template_Key &a)
{
  return a.template_id;
}

CLICK_ENDDECLS
#endif
