#include <config.h>
#include <click/config.h>

#include "aggregateipaddr.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <packet_anno.hh>

AggregateIPAddress::AggregateIPAddress()
  : Element(1, 1)
{
  MOD_INC_USE_COUNT;
}

AggregateIPAddress::~AggregateIPAddress()
{
  MOD_DEC_USE_COUNT;
}

int
AggregateIPAddress::configure(const Vector<String> &conf, ErrorHandler *errh)
{
  String typ;
  unsigned first, nbits;
  if (cp_va_parse(conf, this, errh,
		  cpWord, "address type (src/dst)", &typ,
		  cpUnsigned, "first bit", &first,
		  cpUnsigned, "number of bits", &nbits,
                  0) < 0)
    return -1;

  typ = typ.lower();
  if (typ == "src")
    _offset = 3;
  else if (typ == "dst")
    _offset = 4;
  else
    return errh->error("address type must be `src' or `dst'");

  if (first > 31)
    return errh->error("first bit must be between 0 and 31");
  if (nbits == 0 || nbits > 16)
    return errh->error("number of bits must be between 1 and 16");
  else if (first + nbits > 32)
    return errh->error("bitfield extends beyond end of IP address");

  _shift = first;
  _mask = (1 << nbits) - 1;
  return 0;
}

inline void
AggregateIPAddress::process_packet(Packet *p)
{
  const unsigned *udata =
    reinterpret_cast<const unsigned *>(p->network_header());
  unsigned addr = ntohl(udata[_offset]);
  int row = (addr >> _shift) & _mask;
  SET_AGGREGATE_ANNO(p, row);
}

void
AggregateIPAddress::push(int, Packet *p)
{
  process_packet(p);
  output(0).push(p);
}

Packet *
AggregateIPAddress::pull(int)
{
  Packet *p = input(0).pull();
  if (p)
    process_packet(p);
  return p;
}

ELEMENT_REQUIRES(userlevel false)
EXPORT_ELEMENT(AggregateIPAddress)
