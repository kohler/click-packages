// -*- c-basic-offset: 4 -*-
/*
 * groupipaddr.{cc,hh} -- group IP addresses
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
#include "groupipaddr.hh"
#include <click/handlercall.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/packet_anno.hh>
#include <click/router.hh>
#include <click/integers.hh>

GroupIPAddr::GroupIPAddr()
    : Element(1, 1)
{
    MOD_INC_USE_COUNT;
}

GroupIPAddr::~GroupIPAddr()
{
    MOD_DEC_USE_COUNT;
}

int
GroupIPAddr::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    bool active = true;
    
    if (cp_va_parse(conf, this, errh,
		    cpKeywords,
		    "ACTIVE", cpBool, "active on startup?", &active,
		    0) < 0)
	return -1;
    
    _active = active;
    return 0;
}

int
GroupIPAddr::initialize(ErrorHandler *errh)
{
    if (clear(errh) < 0)
	return -1;
    return 0;
}

void
GroupIPAddr::cleanup(CleanupStage)
{
    IPAddrColors::cleanup();
}

inline bool
GroupIPAddr::update(Packet *p)
{
    const click_ip *iph = p->ip_header();
    if (!_active || !iph)
	return false;

    uint32_t saddr = ntohl(iph->ip_src.s_addr);
    uint32_t daddr = ntohl(iph->ip_dst.s_addr);
    Node *snode = find_node(saddr);
    _allocated = false;
    Node *dnode = find_node(daddr);
    // The act of finding 'dnode' may move 'snode', so we have to find it
    // again. >:(
    if (_allocated)
	snode = find_node(saddr);
    if (!snode || !dnode)
	return false;
    assert(snode == find_node(saddr) && dnode == find_node(daddr));

    // resolve colors
    if (snode->color != NULLCOLOR)
	while (snode->color != _color_mapping[snode->color])
	    snode->color = _color_mapping[snode->color];
    if (dnode->color != NULLCOLOR)
	while (dnode->color != _color_mapping[dnode->color])
	    dnode->color = _color_mapping[dnode->color];
    
    if (snode->color == NULLCOLOR && dnode->color == NULLCOLOR) {
	// allocate two colors
	snode->color = _next_color;
	dnode->color = _next_color + 1;
	_color_mapping.push_back(_next_color);
	_color_mapping.push_back(_next_color + 1);
	_next_color += 2;
    } else if (snode->color == NULLCOLOR)
	snode->color = (dnode->color ^ 1);
    else if (dnode->color == NULLCOLOR)
	dnode->color = (snode->color ^ 1);
    else if ((snode->color & ~1) < (dnode->color & ~1)) {
	_color_mapping[dnode->color] = (snode->color ^ 1);
	_color_mapping[dnode->color ^ 1] = snode->color;
	dnode->color = (snode->color ^ 1);
	_compacted = false;
    } else if ((dnode->color & ~1) < (snode->color & ~1)) {
	_color_mapping[snode->color] = (dnode->color ^ 1);
	_color_mapping[snode->color ^ 1] = dnode->color;
	snode->color = (dnode->color ^ 1);
	_compacted = false;
    } else if (snode->color == dnode->color)
	click_chatter("color conflict: src %s same color as dst %s", IPAddress(iph->ip_src).s().cc(), IPAddress(iph->ip_dst).s().cc());

    return true;
}

void
GroupIPAddr::push(int, Packet *p)
{
    (void) update(p);
    output(0).push(p);
}

Packet *
GroupIPAddr::pull(int)
{
    Packet *p = input(0).pull();
    if (p)
	(void) update(p);
    return p;
}


// HANDLERS

int
GroupIPAddr::write_file_handler(const String &data, Element *e, void *thunk, ErrorHandler *errh)
{
    GroupIPAddr *ac = static_cast<GroupIPAddr *>(e);
    String fn;
    if (!cp_filename(cp_uncomment(data), &fn))
	return errh->error("argument should be filename");
    ac->compress_colors();
    return ac->write_file(fn, (thunk != 0), errh);
}

enum {
    AC_ACTIVE, AC_BANNER, AC_STOP, AC_CLEAR, AC_NCOLORS
};

String
GroupIPAddr::read_handler(Element *e, void *thunk)
{
    GroupIPAddr *ac = static_cast<GroupIPAddr *>(e);
    switch ((int)thunk) {
      case AC_ACTIVE:
	return cp_unparse_bool(ac->_active) + "\n";
      case AC_NCOLORS:
	ac->compact_colors();
	return String(ac->_next_color) + "\n";
      default:
	return "<error>";
    }
}

int
GroupIPAddr::write_handler(const String &data, Element *e, void *thunk, ErrorHandler *errh)
{
    GroupIPAddr *ac = static_cast<GroupIPAddr *>(e);
    String s = cp_uncomment(data);
    switch ((int)thunk) {
      case AC_ACTIVE: {
	  bool val;
	  if (!cp_bool(s, &val))
	      return errh->error("argument to `active' should be bool");
	  ac->_active = val;
	  return 0;
      }
      case AC_STOP:
	ac->_active = false;
	ac->router()->please_stop_driver();
	return 0;
      case AC_CLEAR:
	return ac->clear(errh);
      default:
	return errh->error("internal error");
    }
}

void
GroupIPAddr::add_handlers()
{
    add_write_handler("write_file", write_file_handler, (void *)0);
    add_read_handler("active", read_handler, (void *)AC_ACTIVE);
    add_write_handler("active", write_handler, (void *)AC_ACTIVE);
    add_write_handler("stop", write_handler, (void *)AC_STOP);
    add_read_handler("ncolors", read_handler, (void *)AC_NCOLORS);
    add_write_handler("clear", write_handler, (void *)AC_CLEAR);
}

ELEMENT_REQUIRES(userlevel IPAddrColors)
EXPORT_ELEMENT(GroupIPAddr)
