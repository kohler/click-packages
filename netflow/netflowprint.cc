/*
 * netflowprint.{cc,hh} -- element prints Cisco NetFlow packets
 *
 * Copyright (c) 2001 Mazu Networks, Inc.
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include "netflowpacket.hh"
#include "netflowprint.hh"

#if CLICK_USERLEVEL
# include <stdio.h>
#endif

NetflowPrint::NetflowPrint()
{
#if CLICK_USERLEVEL
  _outfile = 0;
#endif
}

NetflowPrint::~NetflowPrint()
{
}

int
NetflowPrint::configure(Vector<String> &conf, ErrorHandler *errh)
{
  Element *e = 0;

  _verbose = false;
  _records = false;
  _tag = "";
  _template_cache = 0;

  if (cp_va_kparse(conf, this, errh,
		   "LABEL", cpkP, cpString, &_tag,
		   "RECORDS", 0, cpBool, &_records,
		   "VERBOSE", 0, cpBool, &_verbose,
		   "CACHE", 0, cpElement, &e,
#if CLICK_USERLEVEL
		   "OUTFILE", 0, cpFilename, &_outfilename,
#endif
		   cpEnd) < 0)
    return -1;

  if (e && !(_template_cache = (NetflowTemplateCache *)e->cast("NetflowTemplateCache")))
    return errh->error("%s is not a NetflowTemplateCache", e->name().c_str());

  return 0;
}

int
NetflowPrint::initialize(ErrorHandler *errh)
{
#if CLICK_USERLEVEL
  if (_outfilename) {
    _outfile = fopen(_outfilename.c_str(), "wb");
    if (!_outfile)
      return errh->error("%s: %s", _outfilename.c_str(), strerror(errno));
  }
#else
  (void) errh;
#endif
  return 0;
}

void
NetflowPrint::cleanup(CleanupStage)
{
#if CLICK_USERLEVEL
  if (_outfile) {
    fclose(_outfile);
    _outfile = 0;
  }
#endif
}

Packet *
NetflowPrint::simple_action(Packet *p)
{
  NetflowPacket *np = NetflowPacket::netflow_packet(p, _template_cache);
  if (! np)
    return p;
  
  StringAccum sa;
  if (_tag)
    sa << _tag << ": ";

  sa << np->unparse(_verbose);
  if (_records) {
    for (int i = 0; i < np->count(); i++)
      sa << np->unparse_record(i, _tag, _verbose);
  }

#if CLICK_USERLEVEL
  if (_outfile) {
    sa << '\n';
    ignore_result(fwrite(sa.data(), 1, sa.length(), _outfile));
  } else
#endif
  {
    click_chatter("%s", sa.c_str());
  }

  delete np;
  return p;
}

ELEMENT_REQUIRES(NetflowPacket)
EXPORT_ELEMENT(NetflowPrint)
