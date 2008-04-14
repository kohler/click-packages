// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowtemplatecache.{cc,hh} -- caches Netflow V9/IPFIX templates
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#include <click/config.h>
#include "netflowtemplatecache.hh"
#include <click/hashtable.hh>
CLICK_DECLS

bool
NetflowTemplateCache::remove(IPAddress srcaddr, uint32_t source_id, uint16_t template_id)
{
  const Netflow_Template_Key key = { srcaddr, source_id, template_id };

  for (Table::iterator iter = _t.begin(); iter.live(); iter++) {
    if (key == iter.key()) {
      _t.erase(key);
      return true;
    }
  }

  return false;
}

bool
NetflowTemplateCache::remove(IPAddress srcaddr, uint32_t source_id)
{
  bool removed = false;

  for (Table::iterator iter = _t.begin(); iter.live(); iter++) {
    const Netflow_Template_Key key = iter.key();
    if (key.srcaddr == srcaddr && key.source_id == source_id) {
      _t.erase(key);
      removed = true;
    }
  }

  return removed;
}

ELEMENT_REQUIRES(NetflowTemplate)
EXPORT_ELEMENT(NetflowTemplateCache)
CLICK_ENDDECLS
