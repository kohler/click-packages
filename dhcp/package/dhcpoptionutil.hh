#ifndef DHCPOPTIONUTIL_HH
#define DHCPOPTIONUTIL_HH
#include "dhcp_common.hh"
#include <click/string.hh>
#include <click/packet.hh>
namespace DHCPOptionUtil {

unsigned char *getOption(unsigned char *options, int option_val, int *option_size);

void insertMagicCooke(unsigned char **options);

uint32_t rand_exp_backoff(uint32_t backoff_center);

String getNextArg(const String &s);

class StringTokenizer{
public:
  StringTokenizer(const String &s);
  bool hasMoreTokens() const;
  ~StringTokenizer();
  String getNextToken();
  
private:
  char *buf;
  char *curr_ptr;
  int length;
};

Packet *push_dhcp_udp_header(Packet *, IPAddress);
}

#endif
