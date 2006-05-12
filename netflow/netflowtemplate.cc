// -*- mode: c++; c-basic-offset: 2 -*-
//
// netflowtemplate.{cc,hh} -- represents a Netflow V9/IPFIX template
// record
//
// Copyright (c) 2006 Mazu Networks, Inc.
//

#include <click/config.h>
#include "netflowtemplate.hh"
CLICK_DECLS

#include <click/vector.cc>
#if EXPLICIT_TEMPLATE_INSTANCES
template class Vector<NetflowTemplateField>;
#endif

CLICK_ENDDECLS

ELEMENT_PROVIDES(NetflowTemplate)

