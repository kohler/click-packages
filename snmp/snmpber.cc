/*
 * snmpber.{cc,hh} -- routines for encoding and decoding SNMP via BER
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
#include "snmpber.hh"
#include <click/straccum.hh>

#define BER_LEN_1_MAX_OID_COMPONENT 0x0000007F
#define BER_LEN_2_MAX_OID_COMPONENT 0x00003FFF
#define BER_LEN_3_MAX_OID_COMPONENT 0x001FFFFF
#define BER_LEN_4_MAX_OID_COMPONENT 0x0FFFFFFF

SNMPBEREncoder::SNMPBEREncoder()
  : _mem_err(ERR_OK)
{
}

unsigned char *
SNMPBEREncoder::extend(int i)
{
  if (unsigned char *x = (unsigned char *)_sa.extend(i))
    return x;
  else
    return (_mem_err = ERR_MEM, (unsigned char *)0);
}

unsigned char *
SNMPBEREncoder::encode_len(unsigned char *storage, int len)
{
  if (len <= LEN_1_MAX)
    *storage++ = len;
  else if (len <= LEN_2_MAX) {
    *storage++ = 0x81;
    *storage++ = len;
  } else {
    *storage++ = 0x82;
    *storage++ = (len >> 8);
    *storage++ = (len & 0xFF);
  }
  return storage;
}

void
SNMPBEREncoder::encode_len_by_len_len(unsigned char *storage, int len, int len_len)
{
  if (len_len == 1) {
    assert(len <= LEN_1_MAX);
    storage[0] = len;
  } else if (len_len == 2) {
    assert(len <= LEN_2_MAX);
    storage[0] = 0x81;
    storage[1] = len;
  } else if (len_len == 3) {
    assert(len <= LEN_3_MAX);
    storage[0] = 0x82;
    storage[1] = (len >> 8);
    storage[2] = (len & 0xFF);
  } else
    assert(0);
}

SNMPBEREncoder::Status
SNMPBEREncoder::push_sequence(SNMPTag tag)
{
  unsigned char *storage = (unsigned char *)_sa.extend(2);
  if (!storage)
    return (_mem_err = ERR_MEM);
  storage[0] = tag;
  _sequence_start.push_back(_sa.length() - 2);
  _sequence_len_len.push_back(1);
  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::push_long_sequence(SNMPTag tag)
{
  unsigned char *storage = (unsigned char *)_sa.extend(4);
  if (!storage)
    return (_mem_err = ERR_MEM);
  storage[0] = tag;
  _sequence_start.push_back(_sa.length() - 4);
  _sequence_len_len.push_back(3);
  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::pop_sequence()
{
  assert(_sequence_start.size());
  int start = _sequence_start.back();
  int expect_len_len = _sequence_len_len.back();
  _sequence_start.pop_back();
  _sequence_len_len.pop_back();

  int len = _sa.length() - (start + 1 + expect_len_len);
  int len_len = calculate_len_len(len);
  if (len_len > expect_len_len) {
    if (!_sa.extend(len_len - expect_len_len))
      return (_mem_err = ERR_MEM);
    memmove(_sa.data() + start + len_len, _sa.data() + start + expect_len_len, len);
  } else
    len_len = expect_len_len;

  encode_len_by_len_len((unsigned char *)_sa.data() + start + 1, len, len_len);
  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::abort_sequence()
{
  assert(_sequence_start.size());
  int start = _sequence_start.back();
  _sequence_start.pop_back();
  _sequence_len_len.pop_back();
  _sa.pop_back(_sa.length() - start);
  return ERR_INVALID;
}

SNMPBEREncoder::Status
SNMPBEREncoder::encode_snmp_oid(const SNMPOid &oid)
{
  if (oid.size() < 2 || oid[0] > 2 || oid[1] >= 40)
    return ERR_INVALID;
  
  int len = 1;
  for (int i = 2; i < oid.size(); i++) {
    uint32_t component = oid[i];
    if (component <= BER_LEN_1_MAX_OID_COMPONENT)
      len += 1;
    else if (component <= BER_LEN_2_MAX_OID_COMPONENT)
      len += 2;
    else if (component <= BER_LEN_3_MAX_OID_COMPONENT)
      len += 3;
    else if (component <= BER_LEN_4_MAX_OID_COMPONENT)
      len += 4;
    else
      len += 5;
  }

  int len_len = calculate_len_len(len);
  if (len_len < 0)
    return (Status)len_len;

  unsigned char *storage = (unsigned char *)_sa.extend(1 + len_len + len);
  if (!storage)
    return (_mem_err = ERR_MEM);

  // store tag and length
  *storage++ = SNMP_TAG_OID;
  storage = encode_len(storage, len);

  // store OID components
  // first two get special handling
  *storage++ = (oid[0]*40 + oid[1]);

  for (int i = 2; i < oid.size(); i++) {
    uint32_t component = oid[i];
    if (component <= BER_LEN_1_MAX_OID_COMPONENT)
      *storage++ = component;
    else if (component <= BER_LEN_2_MAX_OID_COMPONENT) {
      *storage++ = (component >> 7)	| 0x80;
      *storage++ = component		& 0x7F;
    } else if (component <= BER_LEN_3_MAX_OID_COMPONENT) {
      *storage++ = (component >> 14)	| 0x80;
      *storage++ = (component >> 7)	| 0x80;
      *storage++ = component		& 0x7F;
    } else if (component <= BER_LEN_4_MAX_OID_COMPONENT) {
      *storage++ = (component >> 21)	| 0x80;
      *storage++ = (component >> 14)	| 0x80;
      *storage++ = (component >> 7)	| 0x80;
      *storage++ = component		& 0x7F;
    } else {
      *storage++ = (component >> 28)	| 0x80;
      *storage++ = (component >> 21)	| 0x80;
      *storage++ = (component >> 14)	| 0x80;
      *storage++ = (component >> 7)	| 0x80;
      *storage++ = component		& 0x7F;
    }
  }

  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::encode_octet_string(SNMPTag tag, const unsigned char *s, int len)
{
  if (len < 0 || !s)
    return ERR_INVALID;

  int len_len = calculate_len_len(len);
  if (len_len < 0)
    return (Status)len_len;
  
  unsigned char *storage = (unsigned char *)_sa.extend(1 + len_len + len);
  if (!storage)
    return (_mem_err = ERR_MEM);

  // store tag and length
  *storage++ = tag;
  storage = encode_len(storage, len);

  // store data
  memcpy(storage, s, len);

  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::encode_null()
{
  unsigned char *storage = (unsigned char *)_sa.extend(2);
  if (!storage)
    return (_mem_err = ERR_MEM);

  // store tag and length
  storage[0] = SNMP_TAG_NULL;
  storage[1] = 0;

  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::encode_integer(SNMPTag tag, long value)
{
  if (value >= 0)
    return encode_integer(tag, (unsigned long)value);

  int len;
  if (value >= -0x80)
    len = 3;
  else if (value >= -0x8000)
    len = 4;
  else if (value >= -0x800000)
    len = 5;
  else
    len = 6;
  
  unsigned char *storage = (unsigned char *)_sa.extend(len);
  if (!storage)
    return (_mem_err = ERR_MEM);

  storage[0] = tag;
  storage[1] = len - 2;

  storage[len - 1] = (value & 0xFF);
  if (value < -0x80) {
    storage[len - 2] = ((value >> 8) & 0xFF);
    if (value < -0x8000) {
      storage[len - 3] = ((value >> 16) & 0xFF);
      if (value < -0x800000)
	storage[len - 4] = ((value >> 24) & 0xFF);
    }
  }

  return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::encode_integer(SNMPTag tag, unsigned long value)
{
  int len;
  if (value <= 0x7F)
    len = 3;
  else if (value <= 0x7FFF)
    len = 4;
  else if (value <= 0x7FFFFF)
    len = 5;
  else if (value <= 0x7FFFFFFF)
    len = 6;
  else
    len = 7;
  
  unsigned char *storage = (unsigned char *)_sa.extend(len);
  if (!storage)
    return (_mem_err = ERR_MEM);

  storage[0] = tag;
  storage[1] = len - 2;

  storage[len - 1] = (value & 0xFF);
  if (value > 0x7F) {
    storage[len - 2] = ((value >> 8) & 0xFF);
    if (value > 0x7FFF) {
      storage[len - 3] = ((value >> 16) & 0xFF);
      if (value > 0x7FFFFF) {
	storage[len - 4] = ((value >> 24) & 0xFF);
	if (value > 0x7FFFFFFF)
	  storage[len - 5] = 0;
      }
    }
  }

  return ERR_OK;
}

#if HAVE_INT64_TYPES

SNMPBEREncoder::Status
SNMPBEREncoder::encode_integer(SNMPTag tag, int64_t value)
{
    if (value >= 0)
	return encode_integer(tag, (uint64_t)value);

    int len = 3;
    uint64_t v = -value - 1;
    while (v > 0x7F)
	len++, v >>= 8;
  
    unsigned char *storage = (unsigned char *)_sa.extend(len);
    if (!storage)
	return (_mem_err = ERR_MEM);

    storage[0] = tag;
    storage[1] = len - 2;
    v = -value - 1;
    storage[--len] = (v & 0xFF) ^ 0xFF;
    while (v > 0x7F) {
	v >>= 8;
	storage[--len] = (v & 0xFF) ^ 0xFF;
    }

    return ERR_OK;
}

SNMPBEREncoder::Status
SNMPBEREncoder::encode_integer(SNMPTag tag, uint64_t value)
{
    int len = 3;
    uint64_t v = value;
    while (v > 0x7F)
	len++, v >>= 8;
  
    unsigned char *storage = (unsigned char *)_sa.extend(len);
    if (!storage)
	return (_mem_err = ERR_MEM);

    storage[0] = tag;
    storage[1] = len - 2;
    storage[--len] = (value & 0xFF);
    while (value > 0x7F) {
	value >>= 8;
	storage[--len] = (value & 0xFF);
    }

    return ERR_OK;
}

#endif

ELEMENT_REQUIRES(SNMPBasics)
ELEMENT_PROVIDES(SNMPBER)
