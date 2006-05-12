// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowtemplate.{cc,hh} -- represents a Netflow V9/IPFIX template
// record
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#ifndef NETFLOWTEMPLATE_HH
#define NETFLOWTEMPLATE_HH

#include <click/vector.hh>
CLICK_DECLS

class NetflowTemplateField {

public:

  NetflowTemplateField(uint32_t enterprise, uint16_t type, uint16_t length)
    : _enterprise(enterprise), _type(type), _length(length) { }

  uint32_t enterprise() const { return _enterprise; }
  uint16_t type() const { return _type; }
  uint16_t length() const { return _length; }

private:
  uint32_t _enterprise;		/* Enterprise number */
  uint16_t _type;		/* Field type (see below) */
  uint16_t _length;		/* Length in bytes of field value, 65535 means variable length */
};

class NetflowTemplate : public Vector<NetflowTemplateField> {

public:

  NetflowTemplate() { }

  unsigned length() const {
    unsigned ret = 0;

    for (int i = 0; i < size(); i++) {
      if (at(i).length() != 65535) {
	// Do not include variable length fields in the total
	ret += at(i).length();
      }
    }

    return ret;
  }
};

#endif
