#ifndef SR2LINKMETRIC_HH
#define SR2LINKMETRIC_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
#include "sr2ettstat.hh"
CLICK_DECLS

class SR2LinkMetric : public Element {
public:
  SR2LinkMetric();
  virtual ~SR2LinkMetric();

  int configure(Vector<String> &, ErrorHandler *);

protected:
  class LinkTable *_link_table;

};

CLICK_ENDDECLS
#endif
