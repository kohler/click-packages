// -*- c-basic-offset: 4 -*-
#ifndef CLICK_GROUPIPADDR_HH
#define CLICK_GROUPIPADDR_HH
#include <click/element.hh>
class HandlerCall;

class GroupIPAddr : public Element { public:
  
    GroupIPAddr();
    ~GroupIPAddr();
  
    const char *class_name() const	{ return "GroupIPAddr"; }
    const char *processing() const	{ return AGNOSTIC; }
    GroupIPAddr *clone() const		{ return new GroupIPAddr; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

    bool ok(ErrorHandler * = 0) const;
    int ncolors() const			{ return _next_color; }
    
    inline bool update(Packet *);
    void push(int, Packet *);
    Packet *pull(int);

    int clear(ErrorHandler * = 0);
    void compact_colors();
    void compress_colors();
    int write_file(String filename, bool, ErrorHandler *);
    
  private:

    typedef uint32_t color_t;
    static const color_t NULLCOLOR = 0xFFFFFFFFU;
    static const color_t BADCOLOR = 0xFFFFFFFEU;
    
    struct Node {
	uint32_t aggregate;
	color_t color;
	Node *child[2];
    };

    Node *_root;
    Node *_free;
    Vector<Node *> _blocks;

    color_t _next_color;
    Vector<color_t> _color_mapping;

    bool _active : 1;
    bool _compacted : 1;
    bool _allocated : 1;
    color_t _n_fixed_colors;
    
    Node *new_node();
    Node *new_node_block();
    void free_node(Node *);

    uint32_t node_ok(Node *, int, uint32_t *, color_t, ErrorHandler *) const;
    
    Node *make_peer(uint32_t, Node *, bool frozen);
    Node *find_node(uint32_t, bool frozen = false);
    void clear_node(Node *);
    void compact_colors_node(Node *);
    static color_t mark_subcolors_node(Node *);
    static void nearest_colored_ancestors_node(Node *, color_t, int, Vector<color_t> &, Vector<int> &);
    void compress_cycle(Vector<color_t> &, Vector<int> &);

    static String read_handler(Element *, void *);
    static int write_handler(const String &, Element *, void *, ErrorHandler*);
    static void write_nodes(Node*, FILE*, bool, uint32_t*, int&, int, ErrorHandler*);
    static int write_file_handler(const String &, Element *, void *, ErrorHandler*);
    
};

inline GroupIPAddr::Node *
GroupIPAddr::new_node()
{
    if (_free) {
	Node *n = _free;
	_free = n->child[0];
	return n;
    } else
	return new_node_block();
}

inline void
GroupIPAddr::free_node(Node *n)
{
    n->child[0] = _free;
    _free = n;
}

#endif
