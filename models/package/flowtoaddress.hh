// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_FLOWTOADDRESS_HH
#define CLICK_FLOWTOADDRESS_HH
#include <click/element.hh>
#include <click/ipflowid.hh>
#include <click/bighashmap.hh>

/*
=c

FlowToAddress([I<KEYWORDS>])

=s

collects information about TCP flows

Keywords are:

=over 8

=item BIDI

Boolean.

=back

*/

class FlowToAddress : public Element { public:

    FlowToAddress();
    ~FlowToAddress();

    const char *class_name() const	{ return "FlowToAddress"; }
    FlowToAddress *clone() const	{ return new FlowToAddress; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    Packet *simple_action(Packet *);
    
  private:

    typedef BigHashMap<IPFlowID, IPAddress> Map;
    Map _tcp_map;
    Map _udp_map;
    
    IPAddress _next;
    bool _bidi;
    bool _ports;

};

#endif
