#ifndef CHECKDHCPCOOKIE_HH
#define CHECKDHCPCOOKIE_HH

#include <click/element.hh>


/*
 * =c
 * CheckDHCPMsg(request/reply)
 * =s 
 * Checks to see if an incoming packet is, in fact, a valid DHCP Message.
 * 
 * =d
 *
 * On the client side, the first argument needs to be a
 * reply. On the server side, the first arguement is
 * reply.
 * 
 * If a packet is classified as valid, it will be pushed out on
 * outgoing port 0. Otherwise, discarded by default, if port 1 is not
 * connected to any elemenets.
 *
 *
 * =e CheckDHCPCookie(request) or
 *    
 *    CheckDHCPCookie(reply)
 *
 */

class CheckDHCPMsg : public Element {

public:
  
  CheckDHCPMsg();
  ~CheckDHCPMsg();
  
  const char *class_name() const	{ return "CheckDHCPMsg"; }
  const char *port_count() const	{ return "1/1-2"; }
  const char *processing() const	{ return AGNOSTIC; }
  int configure(Vector<String> &conf, ErrorHandler *errh);
  
  Packet *simple_action(Packet *);
  //int initialize(ErrorHandler *);
  
private:
  enum CHECK_TYPE
  {
    CHECK_REQ = 0,
    CHECK_REP
  };
  
  Packet* drop(Packet *p);
  CHECK_TYPE _checkType;
  
};

#endif
