/*
 * snmpoidinfo.{cc,hh} -- element stores SNMP oid information
 * Eddie Kohler
 *
 * Copyright (c) 2000 Mazu Networks, Inc.
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
#include "snmpoidinfo.hh"
#include <click/router.hh>
#include <click/error.hh>
#include <click/straccum.hh>

SNMPOidInfo::SNMPOidInfo()
  : _map(-1)
{
}

SNMPOidInfo::~SNMPOidInfo()
{
}

SNMPOidInfo *
SNMPOidInfo::find_element(const Element *context)
{
  if (context && context->router()) {
    if (void *a = context->router()->attachment("SNMPOidInfo"))
      return (SNMPOidInfo *)a;
  }
  return 0;
}

bool
SNMPOidInfo::query(const String &identifier, String context, SNMPOid *result) const
{
  while (1) {
    int val = _map[identifier];
    while (val >= 0) {
      if (context == _context[val]) {
	extract_tree_oid(val, result);
	return true;
      }
      val = _next[val];
    }

    if (!context)
      return false;
    int slash = context.find_right('/');
    context = context.substring(0, (slash >= 0 ? slash : 0));
  }
}

int
SNMPOidInfo::add_info(const String &arg, const String &prefix, ErrorHandler *errh)
{
  String new_identifier;
  SNMPOid oid;

  if (Args(this, errh).push_back_words(arg)
      .read_mp("NAME", SNMPIdentifierArg(), new_identifier)
      .read_mp("OID", SNMPOidArg(), oid)
      .complete() < 0)
    return -1;

  // check against well-known values
  if (this != well_known_oids) {
    int well_known_map = well_known_oids->_map.get(new_identifier);
    if (well_known_map >= 0) {
      SNMPOid old_oid;
      well_known_oids->extract_tree_oid(well_known_map, &old_oid);
      if (old_oid != oid)
	return errh->error("new definition of SNMP object ID %<%s%> (%s)\n  conflicts with well-known definition (%s)", new_identifier.c_str(), SNMPOidArg::unparse(oid).c_str(), SNMPOidArg::unparse(old_oid).c_str());
      else
	return 0;
    }
  }

  int prev_map = _map.get(new_identifier);

  if (prev_map >= 0) {
    // check against existing values
    while (1) {
      if (prefix == _context[prev_map]) {
	SNMPOid old_oid;
	extract_tree_oid(prev_map, &old_oid);
	if (old_oid != oid)
	  return errh->error("new definition of SNMP object ID %<%s%> (%s)\n  conflicts with old definition (%s)", new_identifier.c_str(), SNMPOidArg::unparse(oid).c_str(), SNMPOidArg::unparse(old_oid).c_str());
      }
      if (_next[prev_map] < 0)
	break;
      prev_map = _next[prev_map];
    }
  }

  // insert into tree
  if (SNMPOidTree::Node *tree_ptr = _tree.insert(oid, 0)) {
    _context.push_back(prefix);
    _next.push_back(-1);
    _tree_ptr.push_back(tree_ptr);
    if (prev_map < 0)
      _map[new_identifier] = _context.size() - 1;
    else
      _next[prev_map] = _context.size() - 1;
  }

  return 0;
}

int
SNMPOidInfo::configure(Vector<String> &conf, ErrorHandler *errh)
{
  // find prefix, which does not include slash
  int last_slash = name().find_right('/');
  String prefix = name().substring(0, (last_slash >= 0 ? last_slash : 0));
  int before = errh->nerrors();

  // put everything in the first SNMPOidInfo
  SNMPOidInfo *soi = find_element(this);
  // if no soi, then use ourself (happens when configuring well_known_oids)
  if (!soi) {
    if (router())
      router()->set_attachment("SNMPOidInfo", this);
    soi = this;
  }

  for (int i = 0; i < conf.size(); i++)
    soi->add_info(conf[i], prefix, errh);

  return (errh->nerrors() == before ? 0 : -1);
}

ELEMENT_REQUIRES(SNMPBasics SNMPOidTree)
EXPORT_ELEMENT(SNMPOidInfo)
