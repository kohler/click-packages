#ifndef CLICK_SNMPBASICS_HH
#define CLICK_SNMPBASICS_HH
#include <click/element.hh>
#include <click/args.hh>

typedef Vector<uint32_t> SNMPOid;
bool snmp_oid_eq(const SNMPOid &, const SNMPOid &, int);
bool operator==(const SNMPOid &, const SNMPOid &);
bool operator!=(const SNMPOid &, const SNMPOid &);
bool operator<=(const SNMPOid &, const SNMPOid &);
bool operator>=(const SNMPOid &, const SNMPOid &);
bool operator<(const SNMPOid &, const SNMPOid &);
bool operator>(const SNMPOid &, const SNMPOid &);

struct SNMPIdentifierArg {
    static bool parse(const String &str, String &result, const ArgContext &args = blank_args);
};

struct SNMPOidArg {
    static bool parse(const String &str, SNMPOid &result, const ArgContext &args);
    static String unparse(const SNMPOid &oid);
};

struct SNMPVariableArg {
    static bool parse(const String &str, int &result, const ArgContext &args);
};

uint32_t snmp_time_ticks_since(uint32_t);

enum {
  SNMP_VERSION_1 = 0,
};

enum SNMPTag {
  SNMP_TAG_INVALID = -1,
  SNMP_TAG_INTEGER = 0x02,
  SNMP_TAG_OCTET_STRING = 0x04,
  SNMP_TAG_NULL = 0x05,
  SNMP_TAG_OID = 0x06,
  SNMP_TAG_SEQUENCE = 0x30,
  SNMP_TAG_IPADDRESS = 0x40,
  SNMP_TAG_COUNTER = 0x41,
  SNMP_TAG_GAUGE = 0x42,
  SNMP_TAG_TIMETICKS = 0x43,
  SNMP_TAG_OPAQUE = 0x44,
  SNMP_TAG_COUNTER64 = 0x46,
  SNMP_TAG_V1_GET = 0xA0,
  SNMP_TAG_V1_GETNEXT = 0xA1,
  SNMP_TAG_V1_RESPONSE = 0xA2,
  SNMP_TAG_V1_SET = 0xA3,
  SNMP_TAG_V1_TRAP = 0xA4,
  // fake tags: values > 256, truncated on assignment
  SNMP_TAG_DISPLAYSTRING = 0x104,
};

enum SNMPDataFormat {
  SNMP_FMT_INVALID = -1,
  SNMP_FMT_INTEGER = 1,
  SNMP_FMT_OCTET_STRING,
  SNMP_FMT_NULL,
  SNMP_FMT_OID,
  SNMP_FMT_IPADDRESS,
  SNMP_FMT_INTEGER64
};

enum SNMPConfigurePhases {
  CONFIGURE_PHASE_SNMP_OIDINFO = Element::CONFIGURE_PHASE_FIRST,
  CONFIGURE_PHASE_SNMP_VARINFO = Element::CONFIGURE_PHASE_INFO,
};

SNMPTag snmp_parse_tag(const String &);
SNMPDataFormat snmp_tag_format(SNMPTag);

inline bool
operator==(const SNMPOid &a, const SNMPOid &b)
{
  return a.size() == b.size() && snmp_oid_eq(a, b, a.size());
}

inline bool
operator!=(const SNMPOid &a, const SNMPOid &b)
{
  return a.size() != b.size() || !snmp_oid_eq(a, b, a.size());
}

inline bool
operator<=(const SNMPOid &a, const SNMPOid &b)
{
  return a.size() <= b.size() && snmp_oid_eq(a, b, a.size());
}

inline bool
operator>=(const SNMPOid &a, const SNMPOid &b)
{
  return b <= a;
}

inline bool
operator<(const SNMPOid &a, const SNMPOid &b)
{
  return a.size() < b.size() && snmp_oid_eq(a, b, a.size());
}

inline bool
operator>(const SNMPOid &a, const SNMPOid &b)
{
  return b < a;
}

#if CLICK_HZ == 100
inline uint32_t
snmp_time_ticks_since(uint32_t j0)
{
  return click_jiffies() - j0;
}
#endif

#endif
