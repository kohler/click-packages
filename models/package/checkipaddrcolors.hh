// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CHECKIPADDRCOLORS_HH
#define CLICK_CHECKIPADDRCOLORS_HH
#include <click/element.hh>
#include "ipaddrcolors.hh"

class CheckIPAddrColors : public Element, public IPAddrColors { public:
  
    CheckIPAddrColors();
    ~CheckIPAddrColors();
  
    const char *class_name() const	{ return "CheckIPAddrColors"; }
    const char *processing() const	{ return AGNOSTIC; }
    CheckIPAddrColors *clone() const	{ return new CheckIPAddrColors; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

    void check(Packet *);
    void push(int, Packet *);
    Packet *pull(int);

  private:

    String _filename;
    uint64_t _npackets;
    uint64_t _n_bad_colors;
    uint64_t _n_bad_pairs;
    uint64_t _n_large_colors;
    bool _verbose;

    void check_error(uint64_t &, const char *, ...);
    static String read_handler(Element *, void *);
    
};

#endif
