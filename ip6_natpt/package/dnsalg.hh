#ifndef DNSALG_HH
#define DNSALG_HH

#include <click/config.h>
#include <clicknet/ip.h>
#include <clicknet/ip6.h>
#include <clicknet/udp.h>
#include <click/dnsmessage.hh>
#include <click/ip6address.hh>
#include <click/ipaddress.hh>
#include <click/router.hh>
#include <click/elemfilter.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include "elements/ip6/addresstranslator.hh"
#include <clicknet/rfc1035.h>
#ifndef CLICK_LINUXMODULE
  #include <string.h>
#endif

CLICK_DECLS


/*
 * DNS Application Level Gateway
 *
 * RFC 1035, DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION (DNS)|http://www.ietf.org/rfc/rfc1035.txt>
 */

class DNSAlg : public Element {

  //Configuration parameters
  AddressTranslator *_at;
  String ipv4_dns_server_ptr_domain;
  String ipv6_dns_server_ptr_domain;
  String ipv4_dns_server_name;
  String ipv6_dns_server_name;

 public:

  DNSAlg();
  ~DNSAlg();

  const char *class_name() const	{ return "DNSAlg"; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void uninitialize();
  void push(int port, Packet *p);
  void translate_ipv4_ipv6(Packet *p);
  void translate_ipv6_ipv4(Packet *p);
  private:
  int get_query_ipv6_address(const char *ptr_domain, char *normal_ipv6_address);
  int get_query_ipv4_address(const char *ptr_domain, char *normal_ipv4_address);
  int extract_ipv4_address_from_ipv6_address(const char * new_ipv6_address, char *ipv4_address);
  void hex_ipv4_to_dec_ipv4(char *hex,int *dec);
  void make_ipv4_ptr_domain(struct in_addr addr, char * ptr_domain);
  void make_ipv4_ptr_domain(int *addr, char * ptr_domain);
  int my_atoi(const char *name);

  bool failed_query;

};
CLICK_ENDDECLS
#endif
