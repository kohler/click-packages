#ifndef DHCPSERVERRLEASE_HH
#define DHCPSERVERRLEASE_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "dhcpserverleases.hh"

class DHCPServerRelease : public Element
{
public:
  DHCPServerRelease();
  ~DHCPServerRelease();

  const char *class_name() const { return "DHCPServerRelease"; }
  const char *processing() const { return PUSH; }
  
  int initialize(ErrorHandler *);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  
  virtual void push(int port, Packet *p);
  
private:
  DHCPServerLeases *_serverLeases;
};

#endif
