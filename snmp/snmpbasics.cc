/*
 * snmpbasics.{cc,hh} -- basic SNMP functions
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
#include "snmpbasics.hh"
#include "snmpoidinfo.hh"
#include "snmpvarinfo.hh"
#include <click/straccum.hh>
#include <click/error.hh>

CpVaParseCmd
  cpSNMPIdentifier = "snmp_identifier",
  cpSNMPOid = "snmp_oid",
  cpSNMPVariable = "snmp_variable";

SNMPOidInfo *SNMPOidInfo::well_known_oids = 0;


// SNMP OID OPERATIONS

bool
snmp_oid_eq(const SNMPOid &a, const SNMPOid &b, int sz)
{
  return sz == 0 || memcmp(&a[0], &b[0], sz * sizeof(uint32_t)) == 0;
}


// PARSING SNMP IDENTIFIERS

// XXX case insensitive ??

bool
SNMPIdentifierArg::parse(const String &str, String &result, const ArgContext &)
{
  // make sure identifier has correct syntax
  const char *data = str.data();
  int len = str.length();

  // check easy syntax things
  if (len == 0 || !isalpha(data[0]) || !isalnum(data[len-1]))
    return false;

  // otherwise, transform underscores to hyphens, prevent adjacent hyphens,
  // and check for bad characters. Don't copy the string unless you have to
  // (because there is an underscore).
  StringAccum sa;
  int last = 0;

  for (int i = 0; i < len; i++) {
    if (isalnum(data[i]))
      /* nada */;
    else if (data[i] == '-') {
      if (data[i-1] == '-' || data[i-1] == '_')
	return false;
    } else if (data[i] == '_') {
      if (data[i-1] == '-' || data[i-1] == '_')
	return false;
      sa << str.substring(last, i - last) << '-';
      last = i + 1;
    } else
      return false;
  }

  if (last > 0) {
    sa << str.substring(last, len - last);
    result = sa.take_string();
  } else
    result = str;
  return true;
}


// PARSING SNMP OIDS

String
SNMPOidArg::unparse(const SNMPOid &oid)
{
  StringAccum sa;
  for (int i = 0; i < oid.size(); i++) {
    if (i) sa << '.';
    sa << oid[i];
  }
  return sa.take_string();
}

bool
SNMPOidArg::parse(const String &arg, SNMPOid &result, const ArgContext &args)
{
  // set up context information
  SNMPOidInfo *snmp_oid_context = SNMPOidInfo::find_element(args.context());
  String snmp_oid_context_prefix;
  if (snmp_oid_context) {
    String name = args.context()->name();
    int slash = name.find_right('/');
    snmp_oid_context_prefix = name.substring(0, (slash >= 0 ? slash : 0));
  }

  const char *data = arg.data();
  int len = arg.length();
  int pos = 0;
  SNMPOid storage;

  // loop over components
  while (pos < len) {

    // find component
    int first = pos;
    bool all_digits = true;
    bool all_alnum = true;
    while (pos < len && data[pos] != '.') {
      if (!isdigit(data[pos]))
	all_digits = false;
      if (!isalnum(data[pos]))
	all_alnum = false;
      pos++;
    }

    // avoid empty components
    if (pos == first) {
      args.error("empty component in SNMP object ID");
      return false;
    }

    // digits always work (unless they are too large)
    if (all_digits) {
      int value;
      (void) cp_integer(arg.substring(first, pos - first), &value);
      if (cp_errno == CPE_OVERFLOW) {
	args.error("number too large in SNMP object ID");
	return false;
      }
      storage.push_back(value);
      // skip over '.', but only if it is not last character
      if (pos < len - 1)
	pos++;
      continue;
    }

    // extract identifier from string
    String identifier;
    if (all_alnum && isalpha(data[first]))
      identifier = arg.substring(first, pos - first);
    else if (!SNMPIdentifierArg::parse(arg.substring(first, pos - first), identifier)) {
      args.error("%<%s%> has bad SNMP identifier syntax", arg.substring(first, pos - first).c_str());
      return false;
    }

    // look up identifier
    SNMPOid identifier_value;
    if (snmp_oid_context && snmp_oid_context->query(identifier, snmp_oid_context_prefix, &identifier_value))
      /* OK */;
    else if (SNMPOidInfo::well_known_oids->query(identifier, snmp_oid_context_prefix, &identifier_value))
      /* OK */;
    else {
      args.error("unknown object ID %<%s%>", identifier.c_str());
      return false;
    }

    // compare identifier value against existing values
    if (identifier_value.size() < storage.size()) {
      args.error("SNMP object ID %<%s%> (%s) too short for context (%s)", identifier.c_str(), unparse(identifier_value).c_str(), unparse(storage).c_str());
      return false;
    }
    for (int i = 0; i < storage.size(); i++)
      if (identifier_value[i] != storage[i]) {
	args.error("SNMP object ID %<%s%> (%s) conflicts with context (%s)", identifier.c_str(), unparse(identifier_value).c_str(), unparse(storage).c_str());
	return false;
      }

    // OK; append identifier value
    for (int i = storage.size(); i < identifier_value.size(); i++)
      storage.push_back(identifier_value[i]);

    // skip over '.', but only if it is not last character
    if (pos < len - 1)
      pos++;
  }

  // Success!
  //args.message("%s = %s", String(arg).c_str(), unparse(storage).c_str());
  result.swap(storage);
  return true;
}


bool
SNMPVariableArg::parse(const String &arg, int &result, const ArgContext &args)
{
  SNMPOid oid;
  if (!SNMPOidArg::parse(arg, oid, args))
    return false;
  int var = SNMPVariableInfo::query(oid, args.context());
  if (var < 0) {
    args.error("SNMP object ID %<%s%> is not a variable", SNMPOidArg::unparse(oid).c_str());
    return false;
  }
  result = var;
  return true;
}


// SNMP TIMETICKS

#if CLICK_HZ != 100
uint32_t
snmp_time_ticks_since(uint32_t j0)
{
    Timestamp tv = Timestamp::now();
    return ((tv.sec() * 100) + (tv.usec() / 10000)) - j0;
}
#endif


// SNMP FORMAT IDENTIFICATION

SNMPTag
snmp_parse_tag(const String &name)
{
  String uname = name.upper();
  if (uname == "INTEGER" || uname == "INTEGER32")
    return SNMP_TAG_INTEGER;
  else if (uname == "OCTET STRING")
    return SNMP_TAG_OCTET_STRING;
  else if (uname == "DISPLAYSTRING")
    return SNMP_TAG_DISPLAYSTRING;
  else if (uname == "NULL")
    return SNMP_TAG_NULL;
  else if (uname == "OBJECT IDENTIFIER")
    return SNMP_TAG_OID;
  else if (uname == "IPADDRESS")
    return SNMP_TAG_IPADDRESS;
  else if (uname == "COUNTER" || uname == "COUNTER32")
    return SNMP_TAG_COUNTER;
  else if (uname == "COUNTER64")
    return SNMP_TAG_COUNTER64;
  else if (uname == "GAUGE" || uname == "GAUGE32" || uname == "UNSIGNED32")
    return SNMP_TAG_GAUGE;
  else if (uname == "TIMETICKS")
    return SNMP_TAG_TIMETICKS;
  else
    return SNMP_TAG_INVALID;
}

SNMPDataFormat
snmp_tag_format(SNMPTag tag)
{
  switch (tag) {

   case SNMP_TAG_INTEGER:
   case SNMP_TAG_COUNTER:
   case SNMP_TAG_GAUGE:
   case SNMP_TAG_TIMETICKS:
    return SNMP_FMT_INTEGER;

#ifdef HAVE_INT64_TYPES
   case SNMP_TAG_COUNTER64:
    return SNMP_FMT_INTEGER64;
#endif

   case SNMP_TAG_OCTET_STRING:
   case SNMP_TAG_DISPLAYSTRING:
   case SNMP_TAG_OPAQUE:
    return SNMP_FMT_OCTET_STRING;

   case SNMP_TAG_NULL:
    return SNMP_FMT_NULL;

   case SNMP_TAG_OID:
    return SNMP_FMT_OID;

   case SNMP_TAG_IPADDRESS:
    return SNMP_FMT_IPADDRESS;

   default:
    return SNMP_FMT_INVALID;

  }
}


// SNMP CP_VA PARSERS AND WELL-KNOWN

static const char *well_known_oids_config =
  "ccitt 0, \
   iso 1, \
   joint-iso-ccitt 2, \
   \
   org 1.3, \
    dod 1.3.6, \
     internet 1.3.6.1, \
      mgmt internet.2, \
       mib mgmt.1, \
       mib-2 mgmt.1, \
      experimental internet.3, \
      private internet.4, \
       enterprises internet.4.1, \
      snmpv2 internet.6, \
      snmpV2 internet.6, \
   \
   system mib-2.1, \
   interfaces mib-2.2, \
   at mib-2.3, \
   ip mib-2.4, \
   icmp mib-2.5, \
   tcp mib-2.6, \
   udp mib-2.7, \
   egp mib-2.8, \
   transmission mib-2.10, \
   snmp mib-2.11";

void
SNMPOidInfo::static_initialize()
{
  ErrorHandler *errh = ErrorHandler::default_handler();

  SNMPOidInfo::well_known_oids = new SNMPOidInfo;

  String config_string = String::make_stable(well_known_oids_config);
  Vector<String> conf;
  cp_argvec(config_string, conf);
  SNMPOidInfo::well_known_oids->configure(conf, errh);
}

void
SNMPOidInfo::static_cleanup()
{
    delete SNMPOidInfo::well_known_oids;
    SNMPOidInfo::well_known_oids = 0;
}

ELEMENT_PROVIDES(SNMPBasics)
ELEMENT_REQUIRES(SNMPOidInfo SNMPVariableInfo)
