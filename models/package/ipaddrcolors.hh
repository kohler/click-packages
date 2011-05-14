// -*- c-basic-offset: 4 -*-
#ifndef CLICK_IPADDRCOLORS_HH
#define CLICK_IPADDRCOLORS_HH
#include <click/string.hh>
#include <click/vector.hh>
#include <cstdio>
class ErrorHandler;

class IPAddrColors { public:

    typedef uint32_t color_t;

    IPAddrColors();
    ~IPAddrColors();

    bool ok(ErrorHandler * = 0) const;

    int ncolors() const			{ return _next_color; }
    color_t color(uint32_t);
    int set_color(uint32_t, color_t);
    int set_color_subtree(uint32_t, int prefix, color_t);

    int clear(ErrorHandler * = 0);
    void cleanup();
    void compact_colors();
    void compress_colors();

    int read_file(FILE *, ErrorHandler *);
    int read_file(String filename, ErrorHandler *);
    int write_file(String filename, bool binary, ErrorHandler *);

    static const color_t NULLCOLOR = 0xFFFFFFFFU;
    static const color_t MIXEDCOLOR = 0xFFFFFFFEU;
    static const color_t SUBTREECOLOR = 0xFFFFFFFDU;
    static const color_t BADCOLOR = 0xFFFFFFFCU; // MAXCOLOR + 1
    static const color_t MAXCOLOR = 0xFFFFFFFBU;

    struct Node {
	uint32_t aggregate;
	color_t color;
	uint32_t flags;
	Node *child[2];
    };

    enum { F_COLORSUBTREE = 1 };

  protected:

    Node *_root;
    Node *_free;
    Vector<Node *> _blocks;

    color_t _next_color;
    Vector<color_t> _color_mapping;

    bool _compacted : 1;
    bool _allocated : 1;
    color_t _n_fixed_colors;

    Node *new_node();
    Node *new_node_block();
    void free_node(Node *);

    inline int ensure_color(color_t);
    int hard_ensure_color(color_t);

    uint32_t node_ok(Node *, int, uint32_t *, color_t, ErrorHandler *) const;
    static void node_print(const Node *, int, const Node *highlight = 0);

    Node *make_peer(uint32_t, Node *);
    Node *find_node(uint32_t);
    void node_clear(Node *);
    void node_compact_colors(Node *);
    static color_t node_mark_subcolors(Node *);
    static void node_nearest_colored_ancestors(Node *, color_t, int, Vector<color_t> &, Vector<int> &);
    void compress_cycle(Vector<color_t> &, Vector<int> &);

    static void write_nodes(Node *, FILE *, bool, uint32_t *, int &, int, Node *, ErrorHandler *);

};

inline IPAddrColors::Node *
IPAddrColors::new_node()
{
    if (_free) {
	Node *n = _free;
	_free = n->child[0];
	return n;
    } else
	return new_node_block();
}

inline void
IPAddrColors::free_node(Node *n)
{
    n->child[0] = _free;
    _free = n;
}

inline IPAddrColors::color_t
IPAddrColors::color(uint32_t a)
{
    if (Node *n = find_node(a))
	return (n->color <= MAXCOLOR ? _color_mapping[n->color] : n->color);
    else
	return BADCOLOR;
}

inline int
IPAddrColors::ensure_color(color_t c)
{
    return (c < _next_color ? 0 : hard_ensure_color(c));
}

#endif
