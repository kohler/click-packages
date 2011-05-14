// -*- c-basic-offset: 4 -*-
#ifndef CLICK_INFERIPADDRCOLORS_HH
#define CLICK_INFERIPADDRCOLORS_HH
#include <click/element.hh>
#include "ipaddrcolors.hh"

/*
=c

InferIPAddrColors([I<KEYWORDS>])

=s ipmeasure

Infer a graph-coloring for IP addresses.

=d

Takes IP packets on its single input and emits them unchanged, while inferring
a graph coloring for the IP addresses visible on the packets.

InferIPAddrColors assumes that all packets come from a single link, and that
any address corresponds to at most one side of the link. Call the sides red
and blue. Then, every packet has a red source address and a blue destination
address, or vice versa (assuming no source addresses are forged). The
InferIPAddrColors element attempts to infer which addresses are red and which
are blue. Output the coloring by calling the C<write_file> or
C<write_text_file> handler.

Keyword arguments are:

=over 8

=item ACTIVE

Boolean. If false, packets are passed through without affecting the coloring.
Default is true.

=item SEED

Filename. Read this color file for seed colors.

=back

=h write_text_file write-only

Argument is a filename, or `C<->' for standard output. Writes the current
color assignment in text to the specified file.

=h write_file write-only

Argument is a filename, or `C<->' for standard output. Writes the current
color assignment in binary to the specified file.

=h active read/write

Returns or sets the ACTIVE parameter.

=h clear write-only

Erases all accumulated color state when written.

=h stop write-only

Stops the driver, and sets ACTIVE to false, when written.

=h ncolors read-only

Returns the current number of nominal colors. (A written file will have fewer
colors, since this handler doesn't compress the color count using
aggregation.)

=head1 ALGORITHM

InferIPAddrColors works incrementally, but its algorithm is equivalent to this
offline algorithm. Initialize a working set W with all IP addresses seen.
Repeat these steps until W is empty:

=over 3

=item 1.

Initialize two empty sets R and B, corresponding to new "red" and "blue"
colors.

=item 2.

Remove a single address from W and add it to R (color it red).

=item 3.

Remove an address X from W, where the trace pairs X an element of either R or
B. That is, some packet had a red (or blue) address as source address and X as
destination address, or vice versa. Add X to the other color set, so if it was
paired with a red address, add it to B. If X was paired with both red and blue
addresses, then the address graph isn't consistent with our assumptions; add
it to either R or B.

=item 4.

Repeat step 3 until no elements of W were paired with previously colored
addresses by the trace.

=back

These steps result in an initial address coloring, possibly using more than 2
colors. The next step reduces this color count as much as possible using
topological assumptions, namely that red colors cluster close to themselves in
the address space (and the same for blue).

=over 3

=item 1.

Pick a color pair and bless them as RR and BB, primary red and primary blue.
We'll go over the remaining color pairs and merge them into RR and BB. (Conceivably a bad choice of RR and BB might screw up the results.)

=item 2.

Initialize a prefix level P to 31.

=item 3.

Search for a residual color X, not RR and BB, so that some P-aggregate
contains at least one packet colored X; any number of packets with other
residual colors; and some packets with I<at most one> of the colors RR and BB.
That is, the aggregate can contain RR packets but no BB packets, or vice
versa.

If you find such a residual color, then merge that color into the primary
color that it shares an aggregate with, and merge its complement into the
other primary color. For example, if X shares a P-aggregate with RR (but not
BB), then merge X with RR and X's complement with BB. Then return to step 2.

If you find no such color, then decrement P and try step 3 again, unless P is
8 or less, in which case quit.

As a special case, ignore residual colors X whose complements share a
P-aggregate with I<the same> primary color as X.

=back

This will merge most colors together into a single color pair. There may be
some residuals.

=head1 FILE FORMAT

The C<write_text_file> handler writes a text file whose lines consist of an
IP address, a space, and a color number. The C<write_file> handler writes a
binary file, preceded by several lines of text boilerplate. The binary data
starts after a C<$packed_be> or C<$packed_le> line, and consists of many
8-byte records; the first 4 bytes are the IP address in host order, the second
4 the color. Byte order is big-endian for C<$packed_be> and little-endian for
C<$packed_le>.

=a

IPAddrColorPaint, TestIPAddrColors */

class InferIPAddrColors : public Element, public IPAddrColors { public:

    InferIPAddrColors();
    ~InferIPAddrColors();

    const char *class_name() const	{ return "InferIPAddrColors"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *processing() const	{ return AGNOSTIC; }

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
