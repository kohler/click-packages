#include "dhcpoptionutil.hh"

namespace DHCPOptionUtil {

unsigned char* 
getOption(unsigned char *options, int option_val, int *option_size)
{
  unsigned char *curr_ptr = options + 4; //skip the cookie
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

/*
unsigned char* 
getOption(unsigned char *options, int option_val, int *option_size)
{
  while(options[0] != 0xff) {
    click_chatter("option_val : %d | curr: %d", option_val, options[0]);
    if(options[0] == 0) {
      options++;
      continue;
    }
//    if(options[0] == 0xff)
//      return NULL;
    
    if(options[0] == option_val)
    {
      *option_size = *(options + 1);
      return options+2;
    }
    options++;
  }
  return NULL; 
}
*/

inline void insertMagicCooke(unsigned char **options)
{
  //char magic_cookie[4];
  //memcpy(magic_cookie, DHCP_OPTIONS_COOKIE, 4);
  memcpy(*options, &DHCP_OPTIONS_COOKIE, 4);
  *options += 4; 
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

}
