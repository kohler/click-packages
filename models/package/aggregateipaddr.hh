#ifndef AGGREGATEIPADDR_HH
#define AGGREGATEIPADDR_HH
#include <click/element.hh>

/*
=c

AggregateIPAddress(WHAT, FIRSTBIT, NBITS)

=s Aggregates

sets aggregate ID annotation to portion of IP src or dst address

=d 

AggregateIPAddress sets the query row annotation on every passing packet
to a portion of one of the IP addresses in its IP header.

WHAT should be either `C<src>' or `C<dst>', for the IP source or
destination address respectively. FIRSTBIT and NBITS determine the relevant
portion of the IP header. NBITS must be at least one, and can't be more
than 16.

=e

For example,

  AggregateIPAddress(src, 24, 8);

sets the query row annotation to the top byte of each packet's source IP
address (the 8 bits starting at bit 24).

*/

class AggregateIPAddress : public Element { public:

  AggregateIPAddress();
  ~AggregateIPAddress();

  const char *class_name() const	{ return "AggregateIPAddress"; }
  const char *processing() const	{ return AGNOSTIC; }
  AggregateIPAddress *clone() const	{ return new AggregateIPAddress; }

  int configure(Vector<String> &, ErrorHandler *);

  void push(int, Packet *);
  Packet *pull(int);
  
 private:

  unsigned _offset;
  unsigned _shift;
  unsigned _mask;

  inline void process_packet(Packet *);
  
};

#endif
