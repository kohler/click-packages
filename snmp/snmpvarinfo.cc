/*
 * snmpvarinfo.{cc,hh} -- element stores SNMP variable information
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
#include "snmpvarinfo.hh"
#include "snmpber.hh"
#include <click/router.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/handlercall.hh>

SNMPVariableInfo::SNMPVariableInfo()
{
}

SNMPVariableInfo::~SNMPVariableInfo()
{
}

SNMPVariableInfo *
SNMPVariableInfo::find_element(Element *e)
{
  if (e && e->router()) {
    if (void *a = e->router()->attachment("SNMPVariableInfo"))
      return (SNMPVariableInfo *)a;
  }
  return 0;
}

int
SNMPVariableInfo::set_variable_handler(int var, const String &hname, ErrorHandler *errh)
{
  Element *he;
  const Handler *h;

  if (!cp_handler(hname, Handler::OP_READ, &he, &h, this, errh))
    return -1;

  if (_handler_elements[var]
      && (_handler_elements[var] != he || _handlers[var] != h)) {
    SNMPOid oid;
    _tree.extract_oid(_nodes[var], &oid);
    return errh->error("SNMP object ID '%s' redefined", cp_unparse_snmp_oid(oid).c_str());
  }

  _handler_elements[var] = he;
  _handlers[var] = h;
  return 0;
}

int
SNMPVariableInfo::add_info(const String &arg, const String &, ErrorHandler *errh, bool full)
{
  SNMPOid oid;
  String format_name, read_handler;

  if (cp_va_space_kparse(arg, this, errh,
			 "OID", cpkP+cpkM, cpSNMPOid, &oid,
			 "TYPE", cpkP+cpkM, cpString, &format_name,
			 "HANDLER", cpkP, cpArgument, &read_handler,
			 cpEnd) < 0)
    return -1;

  SNMPTag tag = snmp_parse_tag(format_name);
  if (tag < 0)
    return errh->error("bad data format '%s'", format_name.c_str());

  if (!read_handler && tag != SNMP_TAG_NULL)
    return errh->error("must supply a handler for data format '%s'", format_name.c_str());

  // find OID
  SNMPOidTree::Node *np = _tree.force_node(oid);
  if (!np)			// out of memory
    return errh->error("out of memory!");

  int first = _tree.node_data(np);
  if (first >= 0) {
    if (_tags[first] != tag)
      return errh->error("SNMP object ID '%s' variable redefined", cp_unparse_snmp_oid(oid).c_str());
    return (full ? set_variable_handler(first, read_handler, errh) : 0);
  }

  int new_i = _tags.size();
  _tags.push_back(tag);
  _handler_elements.push_back(0);
  _handlers.push_back(0);
  _nodes.push_back(np);
  _tree.set_node_data(np, new_i);
  return (full ? set_variable_handler(new_i, read_handler, errh) : 0);
}

int
SNMPVariableInfo::do_configure(Vector<String> &conf, bool full, ErrorHandler *errh)
{
  // find prefix, which does not include slash
  int last_slash = name().find_right('/');
  String prefix = name().substring(0, (last_slash >= 0 ? last_slash : 0));
  int before = errh->nerrors();
  
  // put everything in the first SNMPVariableInfo
  SNMPVariableInfo *svi = find_element(this);
  if (!svi) {
    router()->set_attachment("SNMPVariableInfo", this);
    svi = this;
  }

  for (int i = 0; i < conf.size(); i++)
    svi->add_info(conf[i], prefix, errh, full);

  return (errh->nerrors() == before ? 0 : -1);
}

int
SNMPVariableInfo::configure(Vector<String> &conf, ErrorHandler *errh)
{
  return do_configure(conf, false, errh);
}

int
SNMPVariableInfo::initialize(ErrorHandler *errh)
{
  Vector<String> conf;
  configuration(conf);
  return do_configure(conf, true, errh);
}

SNMPVariable
SNMPVariableInfo::query(const SNMPOid &oid, Element *context)
{
  SNMPVariableInfo *v = find_element(context);
  if (!v)
    return -1;

  // find variable
  int length;
  int data = v->_tree.find_prefix(oid, &length);
  if (data < 0 || length < oid.size() - 1 || oid.back() != 0)
    return -1;
  else
    return data;
}

bool
SNMPVariableInfo::int_value(SNMPVariable var, Element *context, int *result)
{
  SNMPVariableInfo *v = find_element(context);
  if (!v || snmp_tag_format((SNMPTag)v->_tags[var]) != SNMP_FMT_INTEGER)
    return false;
  if (const Handler *h = v->_handlers[var]) {
    String x = cp_uncomment(h->call_read(v->_handler_elements[var]));
    return cp_integer(x, result);
  } else
    return false;
}

bool
SNMPVariableInfo::unsigned_value(SNMPVariable var, Element *context, unsigned *result)
{
  SNMPVariableInfo *v = find_element(context);
  if (!v || snmp_tag_format((SNMPTag)v->_tags[var]) != SNMP_FMT_INTEGER)
    return false;
  if (const Handler *h = v->_handlers[var]) {
    String x = cp_uncomment(h->call_read(v->_handler_elements[var]));
    return cp_unsigned(x, result);
  } else
    return false;
}

bool
SNMPVariableInfo::encode_binding(SNMPVariable var, SNMPBEREncoder &ber, Element *context)
{
  SNMPVariableInfo *v = find_element(context);
  if (!v)
    return false;

  SNMPTag tag = (SNMPTag)v->_tags[var];

  String str;
  if (tag != SNMP_TAG_NULL) {
    if (const Handler *h = v->_handlers[var])
      str = h->call_read(v->_handler_elements[var]);
  }

  ber.push_sequence();

  // encode OID
  SNMPOid oid;
  v->_tree.extract_oid(v->_nodes[var], &oid);
  oid.push_back(0);
  ber.encode_snmp_oid(oid);

  // encode data
  switch (tag) {

   case SNMP_TAG_OCTET_STRING:
    ber.encode_octet_string(str);
    break;

   case SNMP_TAG_DISPLAYSTRING: {
     if (str.length() && str.back() == '\n')
       str = str.substring(0, -1);
     if (str.length() > 255)
       return (ber.abort_sequence(), false);
     ber.encode_octet_string(str);
     break;
   }
   
   case SNMP_TAG_NULL:
    ber.encode_null();
    break;
    
   case SNMP_TAG_INTEGER: {
     int i;
     if (!cp_integer(cp_uncomment(str), &i))
       return (ber.abort_sequence(), false);
     ber.encode_integer(tag, i);
     break;
   }

   case SNMP_TAG_OID: {
     SNMPOid oid;
     if (!cp_snmp_oid(cp_uncomment(str), context, &oid))
       return (ber.abort_sequence(), false);
     ber.encode_snmp_oid(oid);
     break;
   }
   
   case SNMP_TAG_IPADDRESS: {
     IPAddress ipa;
     if (!cp_ip_address(cp_uncomment(str), &ipa, context))
       return (ber.abort_sequence(), false);
     ber.encode_octet_string(SNMP_TAG_IPADDRESS, ipa.data(), 4);
     break;
   }
   
   case SNMP_TAG_COUNTER:
   case SNMP_TAG_GAUGE:
   case SNMP_TAG_TIMETICKS: { /* XXX - TimeTicks */
     unsigned x;
     if (!cp_unsigned(cp_uncomment(str), &x))
       return (ber.abort_sequence(), false);
     ber.encode_integer(tag, x);
     break;
   }

#if HAVE_INT64_TYPES
   case SNMP_TAG_COUNTER64: {
     uint64_t x;
     if (!cp_unsigned64(cp_uncomment(str), &x))
       return (ber.abort_sequence(), false);
     ber.encode_integer(tag, x);
     break;
   }
#endif

   default:
    return (ber.abort_sequence(), false);

  }

  ber.pop_sequence();
  return true;
}

ELEMENT_REQUIRES(SNMPBasics SNMPOidTree)
EXPORT_ELEMENT(SNMPVariableInfo)
