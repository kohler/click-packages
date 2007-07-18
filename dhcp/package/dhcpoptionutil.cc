#include <click/config.h>
#include <click/glue.hh>
#include <click/packet.hh>
#include <clicknet/udp.h>
#include "dhcpoptionutil.hh"

namespace DHCPOptionUtil {

const uint8_t *fetch_next(Packet *p, int want_option, int &overload,
			  const uint8_t *o)
{
    const dhcpMessage *dm = reinterpret_cast<const dhcpMessage *>(p->transport_header() + sizeof(click_udp));
    const uint8_t *oend;

    // find currently relevant options area
    if (!o) {
	if (p->transport_length() < sizeof(dhcpMessage) - DHCP_OPTIONS_SIZE
	    || dm->magic != DHCP_MAGIC)
	    return 0;
	o = dm->options;
	oend = p->end_data();
	overload = 0;
    } else {
	if (o < dm->sname + sizeof(dm->sname))
	    oend = dm->sname + sizeof(dm->sname);
	else if (o < dm->file + sizeof(dm->file))
	    oend = dm->file + sizeof(dm->file);
	else
	    oend = p->end_data();
	o += 2 + o[1];
    }

  retry:
    while (o + 1 < oend)
	if (*o == DHO_PAD)
	    ++o;
	else if (*o == DHO_END || o + 2 + o[1] > oend)
	    break;
	else if (*o == want_option)
	    return o;
	else if (*o == DHO_DHCP_OPTION_OVERLOAD && overload == 0
		 && o[1] == 1 && o[2] <= 3) {
	    overload = o[2];
	    o += 3;
	} else
	    o += 2 + o[1];

    if (overload == 1 || overload == 3) {
	overload = (overload == 3 ? 2 : 4);
	o = dm->file;
	oend = dm->file + sizeof(dm->file);
	goto retry;
    } else if (overload == 2) {
	overload = 4;
	o = dm->sname;
	oend = dm->sname + sizeof(dm->sname);
	goto retry;
    }

    return 0;
}
    
const uint8_t *fetch(Packet *p, int want_option, int expected_length)
{
    int overload;
    const uint8_t *o = fetch_next(p, want_option, overload);
    return (o && o[1] == expected_length ? o + 2 : 0);
}


unsigned char* 
getOption(unsigned char *options, int option_val, int *option_size)
{
  unsigned char *curr_ptr = options;
  while(curr_ptr[0] != DHO_END)
  {
    //click_chatter("curr_ptr[0] : %d | input: %d", curr_ptr[0], option_val);
    if(curr_ptr[0] == option_val)
    {
      *option_size = *(curr_ptr + 1);
      return curr_ptr+2;
    }
    uint32_t size = *(curr_ptr + 1);
    curr_ptr += (size + 2);
  }
  return NULL;
}

String getNextArg(const String &s)
{
  char buf[256];
  const char * arg = s.data();
  int currIndex = 0;
  
  while( *arg != ',' && *arg != ')' )
  {
    if( *arg == ' ')
    {
      arg++;
      continue;
    }
    buf[currIndex++] = *arg;
    arg++;
  }
  buf[currIndex] = '\0';
  
  return String(buf);
}

StringTokenizer::StringTokenizer(const String &s)
{
  buf = new char[s.length()];
  memcpy(buf, s.data(), s.length());
  curr_ptr = buf;
  length = s.length();
}

StringTokenizer::~StringTokenizer()
{
  delete buf;
}

String StringTokenizer::getNextToken()
{
  char tmp_buf[256];
  memset(tmp_buf, '\0', 256);
  int currIndex = 0;

  while( curr_ptr < (buf + length) )
  {
    if(*curr_ptr == ' ' || *curr_ptr == '\n')
    {
      curr_ptr++;
      break;
    }
    tmp_buf[currIndex++] = *curr_ptr;
    curr_ptr++;
  }
  tmp_buf[currIndex] = '\0';

  String s(tmp_buf);
  //click_chatter("tmp_buf   : %s", tmp_buf);
  //click_chatter("tmp_string: %s %d", s.data(), s.length());
  return s;
}

bool StringTokenizer::hasMoreTokens() const
{
  return curr_ptr < (buf + length);
}

uint32_t rand_exp_backoff(uint32_t backoff_center)
{
    uint32_t dice = random();
    if (dice <= RAND_MAX / 3)
	return backoff_center - 1;
    else if (dice <= (RAND_MAX / 3) * 2)
	return backoff_center;
    else
	return backoff_center + 1;
}


#include <click/atomic.hh>
Packet *
push_dhcp_udp_header(Packet *p_in, IPAddress src) {
	WritablePacket *p = p_in->push(sizeof(click_udp) + sizeof(click_ip));
	click_ip *ip = reinterpret_cast<click_ip *>(p->data());
	click_udp *udp = reinterpret_cast<click_udp *>(ip + 1);
	
	// set up IP header
	ip->ip_v = 4;
	ip->ip_hl = sizeof(click_ip) >> 2;
	ip->ip_len = htons(p->length());
	static atomic_uint32_t id;
	ip->ip_id = htons(id.fetch_and_add(1));
	ip->ip_p = IP_PROTO_UDP;
	ip->ip_src = src;
	ip->ip_dst = IPAddress(~0);
	ip->ip_tos = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 250;
	
	ip->ip_sum = 0;
	ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
	p->set_dst_ip_anno(IPAddress(~0));
	p->set_ip_header(ip, sizeof(click_ip));
	
	// set up UDP header
	udp->uh_sport = htons(67);
	udp->uh_dport = htons(68);
	uint16_t len = p->length() - sizeof(click_ip);
	udp->uh_ulen = htons(len);
	udp->uh_sum = 0;
	unsigned csum = click_in_cksum((unsigned char *)udp, len);
	udp->uh_sum = click_in_cksum_pseudohdr(csum, ip, len);
	return p;
}

}

ELEMENT_PROVIDES(DHCPOptionUtil)
