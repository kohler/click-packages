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
    : Element(1, 1), _root(0), _free(0)
{
    MOD_INC_USE_COUNT;
}

GroupIPAddr::~GroupIPAddr()
{
    MOD_DEC_USE_COUNT;
}

GroupIPAddr::Node *
GroupIPAddr::new_node_block()
{
    assert(!_free);
    int block_size = 1024;
    Node *block = new Node[block_size];
    if (!block)
	return 0;
    _blocks.push_back(block);
    for (int i = 1; i < block_size - 1; i++)
	block[i].child[0] = &block[i+1];
    block[block_size - 1].child[0] = 0;
    _free = &block[1];
    return &block[0];
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
    for (int i = 0; i < _blocks.size(); i++)
	delete[] _blocks[i];
    _blocks.clear();
}

uint32_t
GroupIPAddr::node_ok(Node *n, int last_swivel, uint32_t *nnz_ptr,
		     color_t above_color, ErrorHandler *errh) const
{
    //fprintf(stderr, "%*s%08x: <%u %u %u>\n", (last_swivel < 0 ? 0 : last_swivel), "", n->aggregate, n->child_count[0], n->count, n->child_count[1]);

    if (n->color != NULLCOLOR && n->child[0] && nnz_ptr)
	(*nnz_ptr)++;
    
    if (n->child[0] && n->child[1]) {
	int swivel = first_bit_set(n->child[0]->aggregate ^ n->child[1]->aggregate);
	if (swivel <= last_swivel)
	    return errh->error("%x: bad swivel %d <= %d (%x-%x)", n->aggregate, swivel, last_swivel, n->child[0]->aggregate, n->child[1]->aggregate);
	
	uint32_t mask = (swivel == 1 ? 0 : 0xFFFFFFFFU << (33 - swivel));
	if ((n->child[0]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%x: left child doesn't match upper bits (swivel %d)", n->aggregate, swivel);
	if ((n->child[1]->aggregate & mask) != (n->aggregate & mask))
	    return errh->error("%x: right child doesn't match upper bits (swivel %d)", n->aggregate, swivel);

	mask = (1 << (32 - swivel));
	if ((n->child[0]->aggregate & mask) != 0)
	    return errh->error("%x: left child swivel bit one (swivel %d)", n->aggregate, swivel);
	if ((n->child[1]->aggregate & mask) == 0)
	    return errh->error("%x: right child swivel bit zero (swivel %d)", n->aggregate, swivel);

	mask = (swivel == 1 ? 0xFFFFFFFFU : (1 << (32 - swivel)) - 1);
	if (n->aggregate & mask)
	    return errh->error("%x: lower bits nonzero (swivel %d)", n->aggregate, swivel);

	// check topheaviness
	if (n->color != NULLCOLOR) {
	    if (_n_fixed_colors == 0 || (n->color != BADCOLOR && n->color >= _n_fixed_colors))
		return errh->error("%x: packets present in middle of tree (color %d)", n->aggregate, n->color);
	}

	// check child counts
	color_t subcolor = (n->color == NULLCOLOR ? above_color : n->color);
	(void) node_ok(n->child[0], swivel, nnz_ptr, subcolor, errh);
	(void) node_ok(n->child[1], swivel, nnz_ptr, subcolor, errh);
	
	return 0;
	
    } else if (n->child[0] || n->child[1])
	return errh->error("%x: only one live child", n->aggregate);

    else if (n->color != NULLCOLOR && n->color >= _next_color)
	return errh->error("%x: bad color %d", n->aggregate, n->color);

    else if (n->color != NULLCOLOR && n->color < _n_fixed_colors
	     && above_color < _n_fixed_colors && n->color != above_color)
	return errh->error("%x: an ancestor said children colored %d, but this child colored %d", n->aggregate, above_color, n->color);
    
    else
	return 0;
}

bool
GroupIPAddr::ok(ErrorHandler *errh) const
{
    if (!errh)
	errh = ErrorHandler::default_handler();

    int before = errh->nerrors();
    uint32_t nnz = 0;
    (void) node_ok(_root, 0, &nnz, NULLCOLOR, errh);
    return (errh->nerrors() == before);
}

GroupIPAddr::Node *
GroupIPAddr::make_peer(uint32_t a, Node *n, bool frozen)
{
    /*
     * become a peer
     * algo: create two nodes, the two peers.  leave orig node as
     * the parent of the two new ones.
     */

    if (frozen)
	return 0;
    
    Node *down[2];
    if (!(down[0] = new_node()))
	return 0;
    if (!(down[1] = new_node())) {
	free_node(down[0]);
	return 0;
    }

    // swivel is first bit 'a' and 'n->aggregate' differ
    int swivel = first_bit_set(a ^ n->aggregate);
    // bitvalue is the value of that bit of 'a'
    int bitvalue = (a >> (32 - swivel)) & 1;
    // mask masks off all bits before swivel
    uint32_t mask = (swivel == 1 ? 0 : (0xFFFFFFFFU << (33 - swivel)));

    down[bitvalue]->aggregate = a;
    down[bitvalue]->color = NULLCOLOR;
    down[bitvalue]->child[0] = down[bitvalue]->child[1] = 0;

    *down[1 - bitvalue] = *n;	/* copy orig node down one level */

    n->aggregate = (down[0]->aggregate & mask);
    n->color = NULLCOLOR;
    n->child[0] = down[0];	/* point to children */
    n->child[1] = down[1];

    _allocated = true;
    return down[bitvalue];
}

GroupIPAddr::Node *
GroupIPAddr::find_node(uint32_t a, bool frozen)
{
    // straight outta tcpdpriv
    Node *n = _root;
    while (n) {
	if (n->aggregate == a) {
	    if (n->child[0]) {	// take left child by definition
		n = n->child[0];
		continue;
	    }
	    return (n->color != NULLCOLOR || !frozen ? n : 0);
	}
	if (!n->child[0])
	    n = make_peer(a, n, frozen);
	else {
	    // swivel is the first bit in which the two children differ
	    int swivel = first_bit_set(n->child[0]->aggregate ^ n->child[1]->aggregate);
	    if (first_bit_set(a ^ n->aggregate) < swivel) // input differs earlier
		n = make_peer(a, n, frozen);
	    else if (a & (1 << (32 - swivel)))
		n = n->child[1];
	    else
		n = n->child[0];
	}
    }

    if (!frozen)
	click_chatter("GroupIPAddr: out of memory!");
    return 0;
}

inline bool
GroupIPAddr::update(Packet *p)
{
    const click_ip *iph = p->ip_header();
    if (!_active || !iph)
	return false;

    uint32_t saddr = ntohl(iph->ip_src.s_addr);
    uint32_t daddr = ntohl(iph->ip_dst.s_addr);
    Node *snode = find_node(saddr, false);
    _allocated = false;
    Node *dnode = find_node(daddr, false);
    // The act of finding 'dnode' may move 'snode', so we have to find it
    // again. >:(
    if (_allocated)
	snode = find_node(saddr, false);
    if (!snode || !dnode)
	return false;
    assert(snode == find_node(saddr, false) && dnode == find_node(daddr, false));

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


// CLEAR, REAGGREGATE

void
GroupIPAddr::clear_node(Node *n)
{
    if (n->child[0]) {
	clear_node(n->child[0]);
	clear_node(n->child[1]);
    }
    free_node(n);
}

int
GroupIPAddr::clear(ErrorHandler *errh)
{
    if (_root)
	clear_node(_root);
    
    if (!(_root = new_node())) {
	if (errh)
	    errh->error("out of memory!");
	return -1;
    }
    _root->aggregate = 0;
    _root->color = NULLCOLOR;
    _root->child[0] = _root->child[1] = 0;
    _next_color = 0;
    _compacted = true;
    _n_fixed_colors = 0;
    return 0;
}


void
GroupIPAddr::compact_colors_node(Node *n)
{
    if (n->color < BADCOLOR)
	n->color = _color_mapping[n->color];
    if (n->child[0]) {
	compact_colors_node(n->child[0]);
	compact_colors_node(n->child[1]);
    }
}

void
GroupIPAddr::compact_colors()
{
    // do nothing if already compact
    if (_compacted)
	return;
    
    // resolve color pointer chains
    for (color_t c = 0; c < _next_color; c++) {
	color_t cc = c;
	while (_color_mapping[cc] != cc)
	    _color_mapping[c] = cc = _color_mapping[cc];
    }

    // allocate new colors
    color_t next_color = 0;
    for (color_t c = 0; c < _next_color; c++)
	if (_color_mapping[c] == c)
	    _color_mapping[c] = next_color++;
	else
	    _color_mapping[c] = _color_mapping[ _color_mapping[c] ];

    // change nodes according to mapping
    compact_colors_node(_root);

    // rewrite mapping array
    for (color_t c = 0; c < next_color; c++)
	_color_mapping[c] = c;
    _next_color = next_color;
    _color_mapping.resize(next_color);
    _compacted = true;
}


GroupIPAddr::color_t
GroupIPAddr::mark_subcolors_node(Node *n)
{
    if (!n->child[0])
	return (n->color < 2U ? n->color : NULLCOLOR);
    else {
	color_t lcolor = mark_subcolors_node(n->child[0]);
	color_t rcolor = mark_subcolors_node(n->child[1]);
	if (lcolor == NULLCOLOR)
	    lcolor = rcolor;
	else if (rcolor == NULLCOLOR)
	    rcolor = lcolor;
	if (lcolor != rcolor || lcolor == BADCOLOR)
	    return (n->color = BADCOLOR);
	else
	    return (n->color = lcolor);
    }
}

void
GroupIPAddr::nearest_colored_ancestors_node(Node *n, color_t color, int swivel,
					    Vector<color_t> &colors,
					    Vector<int> &swivels)
{
    if (n->child[0]) {
	if (n->color != NULLCOLOR) {
	    color = n->color;
	    swivel = first_bit_set(n->child[0]->aggregate ^ n->child[1]->aggregate);
	}
	nearest_colored_ancestors_node(n->child[0], color, swivel, colors, swivels);
	nearest_colored_ancestors_node(n->child[1], color, swivel, colors, swivels);
    } else if (n->color != NULLCOLOR && color < BADCOLOR && swivel >= swivels[n->color]) {
	if (swivel == swivels[n->color] && colors[n->color] != color)
	    colors[n->color] = BADCOLOR;
	else
	    colors[n->color] = color;
	swivels[n->color] = swivel;
    }
}

void
GroupIPAddr::compress_cycle(Vector<color_t> &colors, Vector<int> &swivels)
{
    compact_colors();
    _n_fixed_colors = 2;
    (void) mark_subcolors_node(_root);
    colors.assign(ncolors(), NULLCOLOR);
    swivels.assign(ncolors(), -1);
    nearest_colored_ancestors_node(_root, NULLCOLOR, 0, colors, swivels);
}

void
GroupIPAddr::compress_colors()
{
    Vector<color_t> colors;
    Vector<int> swivels;

    compress_cycle(colors, swivels);

    // step back through distances until all done
    int current_distance = 32;
    while (_next_color > 2 && current_distance >= 0) {
	for (color_t c = 2; c < _next_color; c++)
	    if (swivels[c] == current_distance && colors[c] < 2) {
		if (swivels[c^1] == current_distance && colors[c^1] == colors[c]) {
		    click_chatter("color %u conflcit XXX %d/%d", c, swivels[c], swivels[c^1]);
		    continue;
		}
		_color_mapping[c] = colors[c];
		_color_mapping[c^1] = colors[c] ^ 1;
		_compacted = false;
		if ((c&1) == 0)
		    c++;
	    }
	if (_compacted)
	    current_distance--;
	else {
	    compress_cycle(colors, swivels);
	    current_distance = 32;
	}
    }

    for (color_t c = 2; c < _next_color; c++)
	click_chatter("color %u: nearest %u, distance %d", c, colors[c], swivels[c]);
}


// HANDLERS

static void
write_batch(FILE *f, bool binary, uint32_t *buffer, int pos,
	    ErrorHandler *)
{
    if (binary)
	fwrite(buffer, sizeof(uint32_t), pos, f);
    else
	for (int i = 0; i < pos; i += 2)
	    fprintf(f, "%u.%u.%u.%u %u\n", (buffer[i] >> 24) & 255, (buffer[i] >> 16) & 255, (buffer[i] >> 8) & 255, buffer[i] & 255, buffer[i+1]);
}

void
GroupIPAddr::write_nodes(Node *n, FILE *f, bool binary,
			 uint32_t *buffer, int &pos, int len,
			 ErrorHandler *errh)
{
    if (n->color != NULLCOLOR && !n->child[0]) {
	buffer[pos++] = n->aggregate;
	buffer[pos++] = n->color;
	if (pos == len) {
	    write_batch(f, binary, buffer, pos, errh);
	    pos = 0;
	}
    }

    if (n->child[0])
	write_nodes(n->child[0], f, binary, buffer, pos, len, errh);
    if (n->child[1])
	write_nodes(n->child[1], f, binary, buffer, pos, len, errh);
}

int
GroupIPAddr::write_file(String where, bool binary, ErrorHandler *errh)
{
    compact_colors();
    compress_colors();		// XXX
    ok(errh);
    
    FILE *f;
    if (where == "-")
	f = stdout;
    else
	f = fopen(where.cc(), (binary ? "wb" : "w"));
    if (!f)
	return errh->error("%s: %s", where.cc(), strerror(errno));

#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    if (binary)
	fprintf(f, "$packed_be\n");
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    if (binary)
	fprintf(f, "$packed_le\n");
#else
    binary = false;
#endif
    
    uint32_t buf[1024];
    int pos = 0;
    write_nodes(_root, f, binary, buf, pos, 1024, errh);
    if (pos)
	write_batch(f, binary, buf, pos, errh);

    bool had_err = ferror(f);
    if (f != stdout)
	fclose(f);
    if (had_err)
	return errh->error("%s: file error", where.cc());
    else
	return 0;
}

int
GroupIPAddr::write_file_handler(const String &data, Element *e, void *thunk, ErrorHandler *errh)
{
    GroupIPAddr *ac = static_cast<GroupIPAddr *>(e);
    String fn;
    if (!cp_filename(cp_uncomment(data), &fn))
	return errh->error("argument should be filename");
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

ELEMENT_REQUIRES(userlevel)
EXPORT_ELEMENT(GroupIPAddr)
