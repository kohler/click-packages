// -*- c-basic-offset: 4 -*-
#ifndef CLICK_INFERIPADDRCOLORS_HH
#define CLICK_INFERIPADDRCOLORS_HH
#include <click/element.hh>
#include "ipaddrcolors.hh"
class HandlerCall;

class InferIPAddrColors : public Element, public IPAddrColors { public:
  
    InferIPAddrColors();
    ~InferIPAddrColors();
  
    const char *class_name() const	{ return "InferIPAddrColors"; }
    const char *processing() const	{ return AGNOSTIC; }
    InferIPAddrColors *clone() const	{ return new InferIPAddrColors; }

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
