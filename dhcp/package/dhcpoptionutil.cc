#include "dhcpoptionutil.hh"

namespace DHCPOptionUtil {

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

inline void insertMagicCooke(unsigned char **options)
{
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
	static atomic_uint32_t id = 0;
	ip->ip_id = htons(id.read_and_add(1));
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
