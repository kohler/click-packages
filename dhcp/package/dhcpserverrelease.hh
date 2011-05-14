#ifndef DHCPSERVERRLEASE_HH
#define DHCPSERVERRLEASE_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "leasetable.hh"

/*
 * =c
 * DHCPServerRelease(LEASES)
 * =s DHCP
 * handles DHCP release address messages
 */

class DHCPServerRelease : public Element
{
public:
  DHCPServerRelease();
  ~DHCPServerRelease();

  const char *class_name() const { return "DHCPServerRelease"; }
  const char *port_count() const { return PORTS_1_0; }
  const char *processing() const { return PUSH; }

  int configure(Vector<String> &conf, ErrorHandler *errh);

  virtual void push(int port, Packet *p);

private:
  DHCPLeaseTable *_leases;
};

#endif
