// -*- c-basic-offset: 4 -*-
#ifndef CLICK_GROUPIPADDR_HH
#define CLICK_GROUPIPADDR_HH
#include <click/element.hh>
#include "ipaddrcolors.hh"
class HandlerCall;

class GroupIPAddr : public Element, public IPAddrColors { public:
  
    GroupIPAddr();
    ~GroupIPAddr();
  
    const char *class_name() const	{ return "GroupIPAddr"; }
    const char *processing() const	{ return AGNOSTIC; }
    GroupIPAddr *clone() const		{ return new GroupIPAddr; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

    inline bool update(Packet *);
    void push(int, Packet *);
    Packet *pull(int);

  private:

    bool _active : 1;
    
    static String read_handler(Element *, void *);
    static int write_handler(const String &, Element *, void *, ErrorHandler*);
    static void write_nodes(Node*, FILE*, bool, uint32_t*, int&, int, ErrorHandler*);
    static int write_file_handler(const String &, Element *, void *, ErrorHandler*);
    
};

#endif
