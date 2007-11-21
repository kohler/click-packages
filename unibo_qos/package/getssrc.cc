/*
 * GetSSRC.{cc,hh} -- element copies 4 bytes inside the Click packet annotation.
 * (when offset = 50 and packets pertain to an RTP flow, the SSRC field used
 * inside the RTP protocol header is so extracted). The SSRC
 * field identifies each single RTP flow - see RFC 3550.
 *
 * Example of usage in Click Configuration:
 *
 * elementclass class_RTP {
 *    $ssrc, $dscp |
 *    get::GetSSRC($ssrc);
 *    rtp::RTPClassifier;
 *    set::SetIPDSCP($dscp);
 *    input->get[0]->rtp;
 *    get[1]->[1]output;
 *    rtp[0]->set->[0]output;
 *    rtp[1]->[1]output;
 *    }
 *
 *
 * Giorgio Calarco, Carla Raffaelli
 *
 * Copyright (c) 2003 DEIS - Dept.of Electronics, Computer Science and Systems
 * University of Bologna
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
#include "packet_anno.hh"
#include "getssrc.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>

GetSSRC::GetSSRC()
{
}

GetSSRC::~GetSSRC()
{
}

int
GetSSRC::configure(Vector<String> &conf, ErrorHandler *errh)
{
  return cp_va_kparse(conf, this, errh,
		      "OFFSET", cpkP+cpkM, cpUnsigned, &_offset,
		      cpEnd);
}

void
GetSSRC::push(int,Packet *p)
{
    if ((p->length())<(_offset+4))
	output(1).push(p);
    else  {
	uint32_t ssrc = 0;
	for (int i = 0; i < 4; i++)
	    ssrc = (ssrc << 8) | p->data()[_offset + i];
	SET_SSRC_ANNO(p, ssrc);
	output(0).push(p);
    }
}

EXPORT_ELEMENT(GetSSRC)
ELEMENT_MT_SAFE(GetSSRC)
