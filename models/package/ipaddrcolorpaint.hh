// -*- c-basic-offset: 4 -*-
#ifndef CLICK_IPADDRCOLORPAINT_HH
#define CLICK_IPADDRCOLORPAINT_HH
#include <click/element.hh>
#include "ipaddrcolors.hh"

/*
=c

IPAddrColorPaint(FILENAME [, I<KEYWORDS>])

=s ipmeasure

Sets paint annotations based on destination IP address color.

=d

Expects IP packets with destination address annotations set. Looks up the
color for each packet's destination address annotation, and assigns the paint
annotation to the corresponding color. Packets whose addresses have unknown
colors, or colors greater than 255, are dropped (or emitted on output 1, if
present). The file FILENAME contains the relevant IP address coloring.

Keyword arguments are:

=over 8

=item CAREFUL

Boolean. If true, then check that the packet's source and destination
addresses have compatible colors; if not, emit the packet on output 1. Default
is false.

=back

=a

InferIPAddrColors, TestIPAddrColors */

class IPAddrColorPaint : public Element, public IPAddrColors { public:

    IPAddrColorPaint();
    ~IPAddrColorPaint();

    const char *class_name() const	{ return "IPAddrColorPaint"; }
    const char *port_count() const	{ return "1/1-2"; }
    const char *processing() const	{ return "a/ah"; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);

    void push(int, Packet *);
    Packet *pull(int);

  private:

    String _filename;
    bool _careful;

};

#endif
