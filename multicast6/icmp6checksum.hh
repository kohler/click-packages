#ifndef CLICK_ICMP6CHECKSUM_HH
#define CLICK_ICMP6CHECKSUM_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
CLICK_DECLS

/*
 * =c
 * ICMP6Checksum()
 * =s IPv6
 * computes ICMP6 messages checksum
 * =d
 *
 * Expects an IPv6 packet as input. Caclulates RFC 2463/2460 checksum.
 *
 * =a  */

class ICMP6Checksum : public Element {
 

public:
  ICMP6Checksum();
  ~ICMP6Checksum();
  
  const char *class_name() const		{ return "ICMP6Checksum"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }
  WritablePacket *addchecksum(Packet *);
  void printIP6(IP6Address);
  Packet *simple_action(Packet *);

  
private:

  struct hopbyhopheader {
	unsigned char type;
	unsigned char length;
	unsigned short parameter;
	unsigned int empty;
  };
  struct mldv2querie {
	unsigned char type;            // 1 byte
	unsigned char code;            // 1 byte
	unsigned short checksum;       // 2 byte
	unsigned short responsecode;   // 2 byte
	unsigned short reserved;       // 2 byte
	click_in6_addr group;          // 16 byte
	unsigned char res_and_s_and_qrv;       // 1 byte
	unsigned char qqic;            // 1 byte
	unsigned short no_of_sources;  // 2 byte
	//	IP6Address sources[1];
  };


};

CLICK_ENDDECLS
#endif
