#ifndef DHCPOPTIONUTIL_HH
#define DHCPOPTIONUTIL_HH
#include "dhcp_common.hh"
#include <click/string.hh>
#include <click/packet.hh>
namespace DHCPOptionUtil {

const uint8_t *fetch_next(Packet *p, int want_option, int &overload,
			  const uint8_t *o = 0);
const uint8_t *fetch(Packet *p, int want_option, int expected_length);

uint32_t rand_exp_backoff(uint32_t backoff_center);

Packet *push_dhcp_udp_header(Packet *, IPAddress);

}
#endif
