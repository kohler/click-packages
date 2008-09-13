/*
 * sr2txcountmetric.{cc,hh} -- estimated transmission count (`TXCount') metric
 *
 * Copyright (c) 2003 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.  */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include "sr2txcountmetric.hh"
#include "sr2ettstat.hh"
#include <elements/wifi/linktable.hh>
CLICK_DECLS 

SR2TXCountMetric::SR2TXCountMetric()
  : SR2LinkMetric()
{
}

SR2TXCountMetric::~SR2TXCountMetric()
{
}

void
SR2TXCountMetric::update_link(IPAddress from, IPAddress to, 
		       Vector<SR2RateSize>, 
		       Vector<int> fwd, Vector<int> rev, 
		       uint32_t seq)
{
  int metric = 9999;
  if (fwd.size() && rev.size() &&
      fwd[0] && rev[0]) {
    metric = 100 * 100 * 100 / (fwd[0] * rev[0]);
  }

  /* update linktable */
  if (metric && 
      _link_table && 
      !_link_table->update_link(from, to, seq, 0, metric)) {
    click_chatter("%{element} couldn't update link %s > %d > %s\n",
		  this,
		  from.unparse().c_str(),
		  metric,
		  to.unparse().c_str());
  }
  if (metric && 
      _link_table && 
      !_link_table->update_link(to, from, seq, 0, metric)){
    click_chatter("%{element} couldn't update link %s < %d < %s\n",
		  this,
		  from.unparse().c_str(),
		  metric,
		  to.unparse().c_str());
  }
}

EXPORT_ELEMENT(SR2TXCountMetric)
ELEMENT_REQUIRES(bitrate)
ELEMENT_REQUIRES(SR2LinkMetric)
CLICK_ENDDECLS
