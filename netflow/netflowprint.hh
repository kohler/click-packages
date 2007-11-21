#ifndef NETFLOWPRINT_HH
#define NETFLOWPRINT_HH

#include <click/element.hh>
#include <click/string.hh>
#include "netflowtemplatecache.hh"

/*
=c

NetflowPrint([LABEL, KEYWORDS])

=s Mazu Logging

prints human-readable summary of Cisco NetFlow packets

=d

Prints a human-readable summary of Cisco NetFlow packets, optionally preceded
by the TAG text.  Incoming packets must have their IP header annotation set.
Only UDP/IP-encapsulated NetFlow packets are printed, but all packets are
forwarded to the single output port.

Keyword arguments are:

=over 8

=item RECORDS

Boolean. Determines whether to print individual flow records or not.  Default
is false.

=item VERBOSE

Boolean. Determines whether output should be very verbose or not.  Default
is false.

=item CACHE

The name of a NetflowTemplateCache element. If specified, then
NetflowPrint will be able to print data records from Netflow V9
flowsets.

=item OUTFILE

String. Only available at user level. Print information to the file specified
by OUTFILE instead of standard error.

=back

=a

NetflowArrivalCounter, UnsummarizeNetflow */

class NetflowPrint : public Element { 
public:

  NetflowPrint();
  ~NetflowPrint();
  
  const char *class_name() const	{ return "NetflowPrint"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *processing() const	{ return AGNOSTIC; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);
  
  Packet *simple_action(Packet *);

private:

  String _tag;
  bool _verbose;
  bool _records;
  NetflowTemplateCache *_template_cache;

#if CLICK_USERLEVEL
  String _outfilename;
  FILE *_outfile;
#endif

};

#endif
