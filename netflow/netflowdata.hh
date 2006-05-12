// -*- mode: c++; c-basic-offset: 2 -*-
//
// Container class for variable type Netflow V9/IPFIX data record fields
//
// Copyright (C) 2006 Mazu Networks, Inc.
//

#ifndef NETFLOWDATA_HH
#define NETFLOWDATA_HH
#include <click/straccum.hh>
#include <click/string.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/ip6address.hh>
#include <clicknet/ip.h>
#include <clicknet/ip6.h>
#include <clicknet/udp.h>
CLICK_DECLS

class NetflowData {

public:

  NetflowData()
    : _data(0), _parsed(false) { }
  NetflowData(uint32_t enterprise, uint16_t type, const void *data, unsigned length);
  NetflowData(const NetflowData &);
  ~NetflowData();

  // Integral data types and boolean
  template<class T> T value() const {
    switch (sizeof(T)) {
    case 1: return (T)_value.unsigned8;
    case 2: return (T)_value.unsigned16;
    case 4: return (T)_value.unsigned32;
#if HAVE_INT64_TYPES
    case 8: return (T)_value.unsigned64;
#endif
    }
    return (T)0;
  }

  // Floating point data types
  float float32() const { return _value.float32; }
  double float64() const { return _value.float64; }

  // Address types
  EtherAddress etheraddress() const { return _etheraddress; }
  IPAddress ipaddress() const { return _ipaddress; }
#if HAVE_IP6
  IP6Address ip6address() const { return _ip6address; }
#endif

  // String representation of the field value, if any
  String str() const;

  // Enterprise number and field type
  uint32_t enterprise() const { return _enterprise; }
  uint16_t type() const { return _type; }

  // Name of the field type, if any
  String name() const;

  // Field value was recognized and parsed
  bool parsed() const { return _parsed; }

  // Pointer to and length of raw field data
  const unsigned char *data() const { return _data; }
  unsigned length() const { return _length; }

  NetflowData &operator=(const NetflowData &);

private:
  uint32_t _enterprise;
  uint16_t _type;
  unsigned char *_data;
  unsigned _length;

  bool parse();
  bool _parsed;

  void copy_from(const NetflowData &);

  union {
    uint8_t unsigned8;
    uint16_t unsigned16;
    uint32_t unsigned32;
#if HAVE_INT64_TYPES
    uint64_t unsigned64;
#endif
    float float32;
    double float64;
  } _value;
  EtherAddress _etheraddress;
  IPAddress _ipaddress;
#if HAVE_IP6
  IP6Address _ip6address;
#endif
  String _str;
};

#if defined(__i386) && !defined(CLICK_LINUXMODULE)
#if (__GNUC__ == 4) && (__GNUC_MINOR__ == 0) && (__GNUC_PATCHLEVEL__ < 4)

#include <byteswap.h>

static inline uint32_t mazu_swap32(uint32_t x) { return __bswap_constant_32(x); }
static inline uint16_t mazu_swap16(uint16_t x) { return __bswap_constant_16(x); }

#undef ntohl
#undef ntohs
#undef htonl
#undef htons

#define ntohl(x) mazu_swap32(x)
#define ntohs(x) mazu_swap16(x)
#define htonl(x) mazu_swap32(x)
#define htons(x) mazu_swap16(x)

#endif // GCC 4.0.0-4.0.3
#endif // i386

// Helper function to cast possibly unaligned data record fields in network order
template<class T> static inline T
unaligned_ntoh(const void *data)
{
  const uint8_t *d = reinterpret_cast<const uint8_t *>(data);
  switch (sizeof(T)) {
  case 1: return (T)((uint8_t)d[0]);
#ifdef i386
  case 2: return (T)ntohs(*(reinterpret_cast<const uint16_t *>(data)));
  case 4: return (T)ntohl(*(reinterpret_cast<const uint32_t *>(data)));
#else
  case 2: return (T)(((uint16_t)d[0] <<  8) | ((uint16_t)d[1]));
  case 4: return (T)(((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
		     ((uint32_t)d[2] <<  8) | ((uint32_t)d[3]));
#endif
#if HAVE_INT64_TYPES
  case 8: return (T)(((uint64_t)d[0] << 56) | ((uint64_t)d[1] << 48) |
		     ((uint64_t)d[2] << 40) | ((uint64_t)d[3] << 32) |
		     ((uint64_t)d[4] << 24) | ((uint64_t)d[5] << 16) |
		     ((uint64_t)d[6] <<  8) | ((uint64_t)d[7]));
#endif
  }
  return (T)0;
}

CLICK_ENDDECLS
#endif
