// -*- c-basic-offset: 4 -*-
/*
 * testipaddrcolors.{cc,hh} -- test IP address colors by communication
 * patterns
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
#include "testipaddrcolors.hh"
#include <click/handlercall.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <click/straccum.hh>

TestIPAddrColors::TestIPAddrColors()
    : Element(1, 1)
{
    MOD_INC_USE_COUNT;
}

TestIPAddrColors::~TestIPAddrColors()
{
    MOD_DEC_USE_COUNT;
}

int
TestIPAddrColors::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    bool verbose = false;
    if (cp_va_parse(conf, this, errh,
		    cpFilename, "colors filename", &_filename,
		    cpKeywords,
		    "VERBOSE", cpBool, "be verbose?", &verbose,
		    0) < 0)
	return -1;
    _verbose = verbose;
    return 0;
}

int
TestIPAddrColors::initialize(ErrorHandler *errh)
{
    if (clear(errh) < 0 || read_file(_filename, errh) < 0)
	return -1;
    _npackets = _n_bad_colors = _n_bad_pairs = _n_large_colors = 0;
    return 0;
}

void
TestIPAddrColors::cleanup(CleanupStage)
{
    IPAddrColors::cleanup();
}

void
TestIPAddrColors::test_error(uint64_t &counter, const char *format, ...)
{
    counter++;
    if (_verbose) {
	va_list val;
	va_start(val, format);
	ErrorHandler::default_handler()->verror(ErrorHandler::ERR_ERROR, String(), format, val);
	va_end(val);
    }
}

inline void
TestIPAddrColors::test(Packet *p)
{
    const click_ip *iph = p->ip_header();
    if (!iph)
	return;

    _npackets++;
    uint32_t saddr = ntohl(iph->ip_src.s_addr);
    uint32_t daddr = ntohl(iph->ip_dst.s_addr);
    color_t scolor = color(saddr);
    color_t dcolor = color(daddr);

    if (scolor > MAXCOLOR)
	test_error(_n_bad_colors, "src %#.0A: bad color %u", saddr, scolor);
    else if (dcolor > MAXCOLOR)
	test_error(_n_bad_colors, "dst %#.0A: bad color %u", daddr, dcolor);
    else if (scolor != (dcolor ^ 1))
	test_error(_n_bad_pairs, "src %#.0A, dst %#.0A: bad color pair %u, %u", saddr, daddr, scolor, dcolor);
    else if (scolor >= 2)
	_n_large_colors++;
}

void
TestIPAddrColors::push(int, Packet *p)
{
    test(p);
    output(0).push(p);
}

Packet *
TestIPAddrColors::pull(int)
{
    Packet *p = input(0).pull();
    if (p)
	test(p);
    return p;
}


// HANDLERS

enum {
    AC_COUNT, AC_ERROR_COUNT, AC_DETAILS
};

String
TestIPAddrColors::read_handler(Element *e, void *thunk)
{
    TestIPAddrColors *c = static_cast<TestIPAddrColors *>(e);
    switch ((int)thunk) {
      case AC_COUNT:
	return String(c->_npackets) + "\n";
      case AC_ERROR_COUNT:
	return String(c->_n_bad_colors + c->_n_bad_pairs) + "\n";
      case AC_DETAILS: {
	  StringAccum sa;
	  sa << "count " << c->_npackets
	     << "\nbad_color_count " << c->_n_bad_colors
	     << "\nbad_pair_count " << c->_n_bad_pairs
	     << "\nlarge_color_count " << c->_n_large_colors
	     << '\n';
	  return sa.take_string();
      }
      default:
	return "<error>";
    }
}

void
TestIPAddrColors::add_handlers()
{
    add_read_handler("count", read_handler, (void *)AC_COUNT);
    add_read_handler("error_count", read_handler, (void *)AC_ERROR_COUNT);
    add_read_handler("details", read_handler, (void *)AC_DETAILS);
}

ELEMENT_REQUIRES(userlevel IPAddrColors)
EXPORT_ELEMENT(TestIPAddrColors)
