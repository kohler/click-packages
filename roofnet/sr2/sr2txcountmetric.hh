#ifndef SR2TXCOUNTMETRIC_HH
#define SR2TXCOUNTMETRIC_HH
#include <click/element.hh>
#include "sr2linkmetric.hh"
#include <click/hashmap.hh>
#include <click/etheraddress.hh>
#include <clicknet/wifi.h>
#include "sr2ettstat.hh"
#include <elements/wifi/bitrate.hh>
CLICK_DECLS

/*
 * =c
 * SR2ETTMetric
 * =s Wifi
 * Estimated Transmission Count metric (ETX).
 * 
 * =io
 * None
 *
 */

class SR2TXCountMetric : public SR2LinkMetric {
  
public:

  SR2TXCountMetric();
  ~SR2TXCountMetric();
  const char *class_name() const { return "SR2TXCountMetric"; }
  const char *processing() const { return AGNOSTIC; }

  void update_link(IPAddress from, IPAddress to, 
		   Vector<SR2RateSize> rs, 
		   Vector<int> fwd, Vector<int> rev, 
		   uint32_t seq);

};

CLICK_ENDDECLS
#endif
