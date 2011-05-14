// -*- c-basic-offset: 4 -*-
/*
 * ipaddrcolors.{cc,hh} -- IP address color tree
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
#include "ipaddrcolors.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/integers.hh>

#ifdef HAVE_BYTEORDER_H
#include <byteorder.h>
#else
static inline uint32_t bswap_32(uint32_t u) {
    return ((u >> 24) | ((u & 0xff0000) >> 8) | ((u & 0xff00) << 8) | ((u & 0xff) << 24));
}
#endif


const IPAddrColors::color_t IPAddrColors::BADCOLOR, IPAddrColors::NULLCOLOR, IPAddrColors::MIXEDCOLOR, IPAddrColors::SUBTREECOLOR, IPAddrColors::MAXCOLOR;

IPAddrColors::IPAddrColors()
    : _root(0), _free(0)
{
}

IPAddrColors::~IPAddrColors()
{
    cleanup();
}

IPAddrColors::Node *
IPAddrColors::new_node_block()
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

void
IPAddrColors::cleanup()
{
    for (int i = 0; i < _blocks.size(); i++)
	delete[] _blocks[i];
    _blocks.clear();
    _root = _free = 0;
    _color_mapping.clear();
    _next_color = 0;
}

uint32_t
IPAddrColors::node_ok(Node *n, int last_swivel, uint32_t *nnz_ptr,
		      color_t above_color, ErrorHandler *errh) const
{
    //fprintf(stderr, "%*s%08x: <%u %u %u>\n", (last_swivel < 0 ? 0 : last_swivel), "", n->aggregate, n->child_count[0], n->count, n->child_count[1]);

    if (n->color != NULLCOLOR && n->child[0] && nnz_ptr)
	(*nnz_ptr)++;

    if (n->child[0] && n->child[1]) {
	int swivel = ffs_msb(n->child[0]->aggregate ^ n->child[1]->aggregate);
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
	if (n->color <= MAXCOLOR) {
	    if (_n_fixed_colors == 0 || n->color >= _n_fixed_colors)
		errh->error("%x: packets present in middle of tree (color %d)", n->aggregate, n->color);
	}

	// check child counts
	color_t subcolor = (n->color == NULLCOLOR ? above_color : n->color);
	(void) node_ok(n->child[0], swivel, nnz_ptr, subcolor, errh);
	(void) node_ok(n->child[1], swivel, nnz_ptr, subcolor, errh);

	return 0;

    } else if (n->child[0] || n->child[1])
	return errh->error("%x: only one live child", n->aggregate);

    else if (n->color <= MAXCOLOR && n->color >= _next_color)
	return errh->error("%x: bad color %d", n->aggregate, n->color);

    else if (n->color <= MAXCOLOR && n->color < _n_fixed_colors
	     && above_color < _n_fixed_colors && n->color != above_color)
	return errh->error("%x: an ancestor said children colored %d, but this child colored %d", n->aggregate, above_color, n->color);

    else
	return 0;
}

bool
IPAddrColors::ok(ErrorHandler *errh) const
{
    if (!errh)
	errh = ErrorHandler::default_handler();

    int before = errh->nerrors();
    uint32_t nnz = 0;
    (void) node_ok(_root, 0, &nnz, NULLCOLOR, errh);
    return (errh->nerrors() == before);
}

IPAddrColors::Node *
IPAddrColors::make_peer(uint32_t a, Node *n)
{
    /*
     * become a peer
     * algo: create two nodes, the two peers.  leave orig node as
     * the parent of the two new ones.
     */

    Node *down[2];
    if (!(down[0] = new_node()))
	return 0;
    if (!(down[1] = new_node())) {
	free_node(down[0]);
	return 0;
    }

    // swivel is first bit 'a' and 'n->aggregate' differ
    int swivel = ffs_msb(a ^ n->aggregate);
    // bitvalue is the value of that bit of 'a'
    int bitvalue;
    // mask masks off all bits before swivel
    uint32_t mask;

    // We might be asked to make a peer for this node even for the same
    // aggregate if F_COLORSUBTREE is true. Requires rigamarole.
    if (swivel == 0) {
	assert(!n->child[0] && (n->flags & F_COLORSUBTREE));
	bitvalue = 1;
	mask = 0xFFFFFFFEU;
	a |= 1;
    } else {
	bitvalue = (a >> (32 - swivel)) & 1;
	mask = (swivel == 1 ? 0 : (0xFFFFFFFFU << (33 - swivel)));
    }

    down[bitvalue]->aggregate = a;
    down[bitvalue]->color = NULLCOLOR;
    down[bitvalue]->flags = 0;
    down[bitvalue]->child[0] = down[bitvalue]->child[1] = 0;

    *down[1 - bitvalue] = *n;	/* copy orig node down one level */

    n->aggregate = (down[0]->aggregate & mask);
    if (n->aggregate == down[0]->aggregate && (n->flags & F_COLORSUBTREE)) {
	assert(bitvalue == 1 && n->color == down[0]->color);
	n->flags = F_COLORSUBTREE;
	down[0]->color = NULLCOLOR;
	down[0]->flags &= ~F_COLORSUBTREE;
    } else {
	n->color = NULLCOLOR;
	n->flags = 0;
    }
    n->child[0] = down[0];	/* point to children */
    n->child[1] = down[1];

    _allocated = true;
    // check for zero swivel
    return down[swivel ? bitvalue : 0];
}

IPAddrColors::Node *
IPAddrColors::find_node(uint32_t a)
{
    // straight outta tcpdpriv
    Node *n = _root;
    color_t parent_color = NULLCOLOR;

    while (n) {
	if (n->flags & F_COLORSUBTREE)
	    parent_color = n->color;
	else if (n->aggregate == a && n->child[0]) {
	    n = n->child[0];	// take left child by definition
	    continue;
	} else if (n->aggregate == a) {
	    if (n->color == NULLCOLOR)
		n->color = parent_color;
	    return n;
	}

	if (!n->child[0])
	    n = make_peer(a, n);
	else {
	    // swivel is the first bit in which the two children differ
	    int swivel = ffs_msb(n->child[0]->aggregate ^ n->child[1]->aggregate);
	    if (ffs_msb(a ^ n->aggregate) < swivel) // input differs earlier
		n = make_peer(a, n);
	    else if (a & (1 << (32 - swivel)))
		n = n->child[1];
	    else
		n = n->child[0];
	}
    }

    click_chatter("IPAddrColors: out of memory!");
    return 0;
}


int
IPAddrColors::hard_ensure_color(color_t c)
{
    if (c >= _next_color && c <= MAXCOLOR) {
	_color_mapping.resize((c | 1) + 1);
	if (_color_mapping.size() <= (int) c)
	    return -1;
	for (color_t x = _next_color; x <= (c | 1); x++)
	    _color_mapping[x] = x;
	_next_color = (c | 1) + 1;
    }
    return 0;
}

int
IPAddrColors::set_color(uint32_t a, color_t color)
{
    Node *n = find_node(a);
    if (n && ensure_color(color) >= 0) {
	n->color = color;
	return 0;
    } else
	return -1;
}

int
IPAddrColors::set_color_subtree(uint32_t a, int prefix, color_t color)
{
    if (prefix == 32)
	return set_color(a, color);

    // split the tree properly
    if (prefix && (!find_node(a) || !find_node(a ^ (1U << (32 - prefix)))))
	return -1;

    uint32_t mask = (prefix == 0 ? 0 : 0xFFFFFFFFU << (32 - prefix));
    assert((a & ~mask) == 0);

    Node *n = _root;
    while (n) {
	int swivel = (n->child[0] ? ffs_msb(n->child[0]->aggregate ^ n->child[1]->aggregate) : 33);
	if (swivel <= prefix) {
#ifndef NDEBUG
	    uint32_t swivel_mask = (swivel < 2 ? 0 : 0xFFFFFFFFU << (33 - swivel));
	    assert((n->aggregate & swivel_mask) == (a & swivel_mask));
#endif
	    n = n->child[(a >> (32 - swivel)) & 1];
	} else {
	    assert(n->aggregate == a);
	    break;
	}
    }

    if (!n || ensure_color(color) < 0)
	return -1;
    else {
	n->color = color;
	n->flags |= F_COLORSUBTREE;
	return 0;
    }
}


// CLEAR, REAGGREGATE

void
IPAddrColors::node_print(const Node *n, int depth, const Node *highlight)
{
    uint32_t a = n->aggregate;
    const char *highlight_str = (n == highlight ? "  <====" : "");
    if (n->color == NULLCOLOR)
	fprintf(stderr, "%*s%d.%d.%d.%d%s\n", depth, "", (a>>24)&255, (a>>16)&255, (a>>8)&255, a&255, highlight_str);
    else
	fprintf(stderr, "%*s%d.%d.%d.%d: %d%s%s\n", depth, "", (a>>24)&255, (a>>16)&255, (a>>8)&255, a&255, n->color, (n->flags & F_COLORSUBTREE ? " *" : ""), highlight_str);
    if (n->child[0]) {
	node_print(n->child[0], depth + 3, highlight);
	node_print(n->child[1], depth + 3, highlight);
    }
}


void
IPAddrColors::node_clear(Node *n)
{
    if (n->child[0]) {
	node_clear(n->child[0]);
	node_clear(n->child[1]);
    }
    free_node(n);
}

int
IPAddrColors::clear(ErrorHandler *errh)
{
    if (_root)
	node_clear(_root);

    if (!(_root = new_node())) {
	if (errh)
	    errh->error("out of memory!");
	return -1;
    }
    _root->aggregate = 0;
    _root->color = NULLCOLOR;
    _root->flags = 0;
    _root->child[0] = _root->child[1] = 0;

    _next_color = 0;
    _color_mapping.resize(0);
    _compacted = true;
    _n_fixed_colors = 0;
    return 0;
}


void
IPAddrColors::node_compact_colors(Node *n)
{
    if (n->color <= MAXCOLOR)
	n->color = _color_mapping[n->color];
    if (n->child[0]) {
	node_compact_colors(n->child[0]);
	node_compact_colors(n->child[1]);
    }
}

void
IPAddrColors::compact_colors()
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
    node_compact_colors(_root);

    // rewrite mapping array
    for (color_t c = 0; c < next_color; c++)
	_color_mapping[c] = c;
    _next_color = next_color;
    _color_mapping.resize(next_color);
    _compacted = true;
}


IPAddrColors::color_t
IPAddrColors::node_mark_subcolors(Node *n)
{
    if (!n->child[0])
	return (n->color < 2U ? n->color : NULLCOLOR);
    else {
	color_t lcolor = node_mark_subcolors(n->child[0]);
	color_t rcolor = node_mark_subcolors(n->child[1]);
	if (lcolor == NULLCOLOR)
	    lcolor = rcolor;
	else if (rcolor == NULLCOLOR)
	    rcolor = lcolor;
	if (lcolor != rcolor || lcolor == MIXEDCOLOR)
	    return (n->color = MIXEDCOLOR);
	else
	    return (n->color = lcolor);
    }
}

void
IPAddrColors::node_nearest_colored_ancestors(Node *n, color_t color, int swivel,
					     Vector<color_t> &colors,
					     Vector<int> &swivels)
{
    if (n->child[0]) {
	if (n->color != NULLCOLOR) {
	    color = n->color;
	    swivel = ffs_msb(n->child[0]->aggregate ^ n->child[1]->aggregate);
	}
	node_nearest_colored_ancestors(n->child[0], color, swivel, colors, swivels);
	node_nearest_colored_ancestors(n->child[1], color, swivel, colors, swivels);
    } else if (n->color <= MAXCOLOR && color <= MAXCOLOR && swivel >= swivels[n->color]) {
	if (swivel == swivels[n->color] && colors[n->color] != color)
	    colors[n->color] = MIXEDCOLOR;
	else
	    colors[n->color] = color;
	swivels[n->color] = swivel;
    }
}

void
IPAddrColors::compress_cycle(Vector<color_t> &colors, Vector<int> &swivels)
{
    compact_colors();
    _n_fixed_colors = 2;
    (void) node_mark_subcolors(_root);
    colors.assign(ncolors(), NULLCOLOR);
    swivels.assign(ncolors(), -1);
    node_nearest_colored_ancestors(_root, NULLCOLOR, 0, colors, swivels);
}

void
IPAddrColors::compress_colors()
{
    Vector<color_t> colors;
    Vector<int> swivels;

    compress_cycle(colors, swivels);

    // step back through distances until all done
    int current_distance = 32;
    while (_next_color > 2 && current_distance >= 8) {
	for (color_t c = 2; c < _next_color; c++)
	    if (swivels[c] == current_distance && colors[c] < 2) {
		if (swivels[c^1] == current_distance && colors[c^1] == colors[c]) {
		    //click_chatter("color %u conflcit XXX %d/%d", c, swivels[c], swivels[c^1]);
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
write_batch(FILE *f, bool binary, uint32_t *buffer, int &pos,
	    ErrorHandler *)
{
    if (binary)
	ignore_result(fwrite(buffer, sizeof(uint32_t), pos, f));
    else
	for (int i = 0; i < pos; i += 2)
	    if (buffer[i+1] == IPAddrColors::SUBTREECOLOR) {
		fprintf(f, "%u.%u.%u.%u/%u %u\n", (buffer[i] >> 24) & 255, (buffer[i] >> 16) & 255, (buffer[i] >> 8) & 255, buffer[i] & 255, buffer[i+2], buffer[i+3]);
		i += 2;
	    } else
		fprintf(f, "%u.%u.%u.%u %u\n", (buffer[i] >> 24) & 255, (buffer[i] >> 16) & 255, (buffer[i] >> 8) & 255, buffer[i] & 255, buffer[i+1]);
    pos = 0;
}

void
IPAddrColors::write_nodes(Node *n, FILE *f, bool binary,
			  uint32_t *buffer, int &pos, int len,
			  Node *parent, ErrorHandler *errh)
{
    if (n->flags & F_COLORSUBTREE) {
	if (pos > len - 4)
	    write_batch(f, binary, buffer, pos, errh);
	buffer[pos++] = n->aggregate;
	buffer[pos++] = SUBTREECOLOR;
	buffer[pos++] = ffs_msb(parent->child[0]->aggregate ^ parent->child[1]->aggregate);
	buffer[pos++] = n->color;
    } else if (n->color <= BADCOLOR && !n->child[0]) {
	buffer[pos++] = n->aggregate;
	buffer[pos++] = n->color;
	if (pos == len)
	    write_batch(f, binary, buffer, pos, errh);
    }

    if (n->child[0]) {
	write_nodes(n->child[0], f, binary, buffer, pos, len, n, errh);
	write_nodes(n->child[1], f, binary, buffer, pos, len, n, errh);
    }
}

int
IPAddrColors::write_file(String where, bool binary, ErrorHandler *errh)
{
    compact_colors();
    ok(errh);

    FILE *f;
    if (where == "-")
	f = stdout;
    else
	f = fopen(where.c_str(), (binary ? "wb" : "w"));
    if (!f)
	return errh->error("%s: %s", where.c_str(), strerror(errno));

    fprintf(f, "$ncolors %u\n", _next_color);
    if (binary) {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	fprintf(f, "$packed_be\n");
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	fprintf(f, "$packed_le\n");
#else
	binary = false;
#endif
    }

    uint32_t buf[1024];
    int pos = 0;
    write_nodes(_root, f, binary, buf, pos, 1024, 0, errh);
    if (pos)
	write_batch(f, binary, buf, pos, errh);

    bool had_err = ferror(f);
    if (f != stdout)
	fclose(f);
    if (had_err)
	return errh->error("%s: file error", where.c_str());
    else
	return 0;
}


static void
read_color_subtree(FILE *f, IPAddrColors *tree, int file_byte_order,
		   uint32_t *ubuf, size_t i, size_t howmany)
{
    uint32_t a = ubuf[2*i];

    size_t pos;
    if (i == howmany - 1) {
	if (fread(ubuf, 8, 1, f) != 1)
	    return;
	pos = 0;
    } else
	pos = 2*i + 2;

    if (file_byte_order == CLICK_BYTE_ORDER)
	tree->set_color_subtree(a, ubuf[pos], ubuf[pos+1]);
    else
	tree->set_color_subtree(bswap_32(a), bswap_32(ubuf[pos]), bswap_32(ubuf[pos+1]));
}

static void
read_packed_file(FILE *f, IPAddrColors *tree, int file_byte_order)
{
    uint32_t ubuf[BUFSIZ];
    if (file_byte_order == CLICK_BYTE_ORDER) {
	while (!feof(f) && !ferror(f)) {
	    size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
	    for (size_t i = 0; i < howmany; i++)
		if (ubuf[2*i + 1] == IPAddrColors::SUBTREECOLOR)
		    read_color_subtree(f, tree, file_byte_order, ubuf, i++, howmany);
		else
		    tree->set_color(ubuf[2*i], ubuf[2*i + 1]);
	}
    } else {
	while (!feof(f) && !ferror(f)) {
	    size_t howmany = fread(ubuf, 8, BUFSIZ / 2, f);
	    for (size_t i = 0; i < howmany; i++) {
		uint32_t color = bswap_32(ubuf[2*i + 1]);
		if (color == IPAddrColors::SUBTREECOLOR)
		    read_color_subtree(f, tree, file_byte_order, ubuf, i++, howmany);
		else
		    tree->set_color(ubuf[2*i], color);
	    }
	}
    }
}

int
IPAddrColors::read_file(FILE *f, ErrorHandler *errh)
{
    // initialize if necessary
    if (_blocks.size() == 0 && clear(errh) < 0)
	return -1;

    char s[BUFSIZ];
    uint32_t u0, u1, u2, u3, prefix, value;

    while (fgets(s, BUFSIZ, f)) {
	if (strlen(s) == BUFSIZ - 1 && s[BUFSIZ - 2] != '\n')
	    return errh->error("line too long");
	if (s[0] == '$') {
	    if (strcmp(s, "$packed\n") == 0)
		read_packed_file(f, this, CLICK_BYTE_ORDER);
	    else if (strcmp(s, "$packed_le\n") == 0)
		read_packed_file(f, this, CLICK_LITTLE_ENDIAN);
	    else if (strcmp(s, "$packed_be\n") == 0)
		read_packed_file(f, this, CLICK_BIG_ENDIAN);
	} else if (sscanf(s, "%u.%u.%u.%u %u", &u0, &u1, &u2, &u3, &value) == 5
		   && u0 < 256 && u1 < 256 && u2 < 256 && u3 < 256)
	    set_color((u0 << 24) | (u1 << 16) | (u2 << 8) | u3, value);
	else if (sscanf(s, "%u.%u.%u.%u/%u %u", &u0, &u1, &u2, &u3, &prefix, &value) == 6
		 && u0 < 256 && u1 < 256 && u2 < 256 && u3 < 256 && prefix <= 32)
	    set_color_subtree((u0 << 24) | (u1 << 16) | (u2 << 8) | u3, prefix, value);
    }
    if (ferror(f))
	return errh->error("file error");
    return 0;
}

int
IPAddrColors::read_file(String where, ErrorHandler *errh)
{
    FILE *f;
    if (where == "-")
	f = stdin;
    else
	f = fopen(where.c_str(), "rb");
    if (!f)
	return errh->error("%s: %s", where.c_str(), strerror(errno));
    int retval = read_file(f, errh);
    if (f != stdin)
	fclose(f);
    return retval;
}

ELEMENT_REQUIRES(userlevel)
ELEMENT_PROVIDES(IPAddrColors)
