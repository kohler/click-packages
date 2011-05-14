// -*- c-basic-offset: 4 -*-
#ifndef CLICK_TESTIPADDRCOLORS_HH
#define CLICK_TESTIPADDRCOLORS_HH
#include <click/element.hh>
#include "ipaddrcolors.hh"

/*
=c

TestIPAddrColors(FILENAME, I<KEYWORDS>)

=s ipmeasure

tests an IP address coloring

=d

Reads FILENAME, an IP address coloring probably produced by InferIPAddrColors,
and tests incoming packets against that coloring. In particular, it checks
that every address has an assigned color, and that the colors for source and
destination addresses differ (one is red and the other blue). Maintains counts
of various kinds of coloring errors, accessible via handlers, and optionally
prints a message on each error.

=over 8

=item VERBOSE

Boolean. If true, then print a message on every coloring error. Default is
false.

=back

=e

Here are some sample verbose error messages:

   src 1.0.0.1: bad color 98
   src 1.0.0.1, dst 3.0.0.3: bad color pair 98, 98

=h count read-only

Returns the number of packets seen.

=h error_count read-only

Returns the number of packets seen with bad-color and/or bad-color-pair
errors.

=h details read-only

Returns a string detailing the numbers of packets, bad-color errors,
bad-color-pair errors, and large colors (nonprimary colors).

=a

InferIPAddrColors, IPAddrColorPaint */

class TestIPAddrColors : public Element, public IPAddrColors { public:

    TestIPAddrColors();
    ~TestIPAddrColors();

    const char *class_name() const	{ return "TestIPAddrColors"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const	{ return AGNOSTIC; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

    void test(Packet *);
    void push(int, Packet *);
    Packet *pull(int);

  private:

    String _filename;
    uint64_t _npackets;
    uint64_t _n_bad_colors;
    uint64_t _n_bad_pairs;
    uint64_t _n_large_colors;
    bool _verbose;

    static String read_handler(Element *, void *);

};

#endif
