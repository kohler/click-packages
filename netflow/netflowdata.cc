// -*- mode: c++; c-basic-offset: 2 -*-
//
// Container class for variable type data record fields
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#include <click/config.h>
#include <click/glue.hh>
#include "netflowdata.hh"
#include "ipfixtypes.hh"
#ifdef CLICK_USERLEVEL
# include <time.h>
#endif
CLICK_DECLS

// Container class for variable type data record fields
NetflowData::NetflowData(uint32_t enterprise, uint16_t type, const void *data, unsigned length)
  : _enterprise(enterprise), _type(type), _length(length)
{
  // Make a private copy of the raw data so that it can always be
  // referred to in case of parse failure, and so that NetflowExport
  // can use NetflowDataRecords to build up packets.
  _data = new unsigned char[length];
  memcpy(_data, data, length);
  _parsed = parse();
}

bool
NetflowData::parse()
{
  switch (_enterprise) {

  case 0:
    // IETF defined type
    switch (ipfix_datatype(_type)) {

    case IPFIX_macAddress:
      if (_length == 6) {
	_etheraddress = EtherAddress(reinterpret_cast<const unsigned char *>(_data));
	return true;
      }
      break;

    case IPFIX_ipv4Address:
      if (_length == 4) {
	struct in_addr ipv4;
	memcpy(&ipv4, _data, 4);
	_ipaddress = IPAddress(ipv4);
	return true;
      }
      break;

#if HAVE_IP6
    case IPFIX_ipv6Address:
      if (_length == 16) {
	struct click_in6_addr ipv6;
	memcpy(&ipv6, _data, 16);
	_ip6address = IP6Address(ipv6);
	return true;
      }
      break;
#endif

#ifdef CLICK_USERLEVEL
    case IPFIX_float32:
      if (_length == 4) {
	_value.float32 = unaligned_ntoh<float>(_data);
	return true;
      }
      break;

#if 0
    // N.B.: These have not yet been defined in the IPFIX schema,
    // even though they are referenced in the spec.
    case IPFIX_float64:
      if (_length == 8) {
	_value.float64 = unaligned_ntoh<double>(_data);
	return true;
      }
      break;
#endif
#endif

    case IPFIX_string:
      _str = String(reinterpret_cast<const char *>(_data), (int)_length);
      return true;

    default:
      // Unknown or integral type
      break;
    }
    break;

  default:
    // Unknown enterprise specific types
    break;
  }

  // Integral types (signed or unsigned)
  switch (_length) {
  case 1: _value.unsigned8 = unaligned_ntoh<uint8_t>(_data); return true;
  case 2: _value.unsigned16 = unaligned_ntoh<uint16_t>(_data); return true;
  case 4: _value.unsigned32 = unaligned_ntoh<uint32_t>(_data); return true;
#if HAVE_INT64_TYPES
  case 8: _value.unsigned64 = unaligned_ntoh<uint64_t>(_data); return true;
#endif
  default: break;
  }

  return false;
}

NetflowData::~NetflowData()
{
  delete[] _data;
}

// Copy constructors to handle _data management
void
NetflowData::copy_from(const NetflowData &old)
{
  _enterprise = old._enterprise;
  _type = old._type;
  _length = old._length;
  if (old._data != 0) {
    _data = new unsigned char[_length];
    memcpy(_data, old._data, _length);
    _parsed = parse();
  }
}

NetflowData::NetflowData(const NetflowData &old)
  : _data(0), _parsed(false)
{
  copy_from(old);
}

NetflowData &
NetflowData::operator=(const NetflowData &old)
{
  if (&old != this) {
    delete[] _data;
    copy_from(old);
  }
  return *this;
}

// Keep in sync with constructor
String
NetflowData::str() const
{
  if (_parsed) {
    switch (_enterprise) {

    case 0:
      // IETF defined type
      switch (ipfix_datatype(_type)) {

      case IPFIX_macAddress:
	return _etheraddress.unparse();

      case IPFIX_ipv4Address:
	return _ipaddress.unparse();

#if HAVE_IP6
      case IPFIX_ipv6Address:
	return _ip6address.unparse();
#endif

#ifdef CLICK_USERLEVEL
      case IPFIX_dateTimeSeconds: {
	time_t t = (time_t)_value.unsigned32;
	char buf[100];
	size_t len = strftime(buf, sizeof(buf), "%F %T", gmtime(&t));
	return String(buf, len);
      }
#endif

      case IPFIX_string:
	return _str;

#ifdef CLICK_USERLEVEL
      case IPFIX_float32:
	return String((double)_value.float32);
#endif

#if 0
      // N.B.: These have not yet been defined in the IPFIX schema,
      // even though they are referenced in the spec.
#ifdef CLICK_USERLEVEL
      case IPFIX_float64:
	return String(_value.float64);
#endif
      case IPFIX_signed8:
	return String((int)_value.unsigned8);

      case IPFIX_signed16:
	return String((int)_value.unsigned16);

      case IPFIX_signed32:
	return String((int)_value.unsigned32);

#if HAVE_INT64_TYPES
      case IPFIX_signed64:
	return String((int64_t)_value.unsigned64);
#endif
#endif

      default:
	// Unknown or integral type
	break;
      }
      break;

    default:
      // Unknown enterprise specific type
      break;
    }

    // Unsigned integral types
    switch (_length) {
    case 1: return String((unsigned)_value.unsigned8);
    case 2: return String((unsigned)_value.unsigned16);
    case 4: return String((unsigned)_value.unsigned32);
#if HAVE_INT64_TYPES
    case 8: return String((unsigned)_value.unsigned64);
#endif
    }
  }

  return "?";
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(NetflowData)
