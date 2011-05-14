// -*- c-basic-offset: 4 -*-
/*
 * ipaddrcolorpaint.{cc,hh} -- set paint annotation by IP address color
 * Eddie Kohler
 *
 * Copyright (c) 2002 International Computer Science Institute
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
#include "ipaddrcolorpaint.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>

IPAddrColorPaint::IPAddrColorPaint()
{
}

IPAddrColorPaint::~IPAddrColorPaint()
{
}

int
IPAddrColorPaint::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    _careful = false;
    if (Args(conf, this, errh)
	.read_mp("FILENAME", FilenameArg(), _filename)
	.read("CAREFUL", _careful)
	.complete() < 0)
	return -1;
    return 0;
}

int
IPAddrColorPaint::initialize(ErrorHandler *errh)
{
    if (clear(errh) < 0 || read_file(_filename, errh) < 0)
	return -1;
    return 0;
}

void
IPAddrColorPaint::cleanup(CleanupStage)
{
    IPAddrColors::cleanup();
}

void
IPAddrColorPaint::push(int, Packet *p)
{
    color_t c = color(ntohl(p->dst_ip_anno().addr())), d = c ^ 1;
    if (_careful)
	d = (p->ip_header() ? color(ntohl(p->ip_header()->ip_src.s_addr)) : c + 2);
    if (c <= 255 && c == (d ^ 1)) {
	SET_PAINT_ANNO(p, c);
	output(0).push(p);
    } else
	checked_output_push(1, p);
}

Packet *
IPAddrColorPaint::pull(int)
{
    Packet *p = input(0).pull();
    if (p) {
	color_t c = color(ntohl(p->dst_ip_anno().addr())), d = c ^ 1;
	if (_careful)
	    d = (p->ip_header() ? color(ntohl(p->ip_header()->ip_src.s_addr)) : c + 2);
	if (c <= 255 && c == (d ^ 1))
	    SET_PAINT_ANNO(p, c);
	else {
	    checked_output_push(1, p);
	    p = 0;
	}
    }
    return p;
}


ELEMENT_REQUIRES(userlevel IPAddrColors)
EXPORT_ELEMENT(IPAddrColorPaint)
