/*
 * FTPPortMapper6.{cc,hh} -- Translates FTP PORT/EPRT/PASV/EPSV commands
 * in IPv4/IPv6 packets.
 * Juan Luis Baptiste <juancho@linuxmail.org>
 * Pontificia Universidad Javeriana
 * Bogota - Colombia 2002.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#include <click/config.h>  
#include "ftpportmapper6.hh"
#include <clicknet/ip.h>
#include <clicknet/ip6.h>
#include <clicknet/tcp.h>
#include <click/router.hh>
#include <click/elemfilter.hh>
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS
FTPPortMapper6::FTPPortMapper6()
{
  add_input(); /*IPv4 arriving packets */
  add_input(); /*IPv6 arriving packets */
  add_output(); /* IPv4 outgoing translated packets*/
  add_output(); /* IPv6 outgoing translated packets*/
  epsv_found = true;
}

FTPPortMapper6::~FTPPortMapper6()
{
}

int
FTPPortMapper6::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (conf.size() != 1)
    return errh->error("wrong number of arguments; expected `FTPPortMapper6(TCPAddressTranslator element)'");

  // get control packet rewriter
  Element *e = cp_element(conf[0], this, errh);
  if (!e)
    return -1;
  _tcp_a = (TCPAddressTranslator *)e->cast("TCPAddressTranslator");
  if (!_tcp_a)
    return errh->error("first argument must be a TCPAddressTranslator element");
  else
    return 0;
}

int
FTPPortMapper6::initialize(ErrorHandler *errh)
{
  // make sure that _control_rewriter is downstream
  CastElementFilter filter("TCPAddressTranslator");
  Vector<Element *> downstream;
  router()->downstream_elements(this, 0, &filter, downstream);
  filter.filter(downstream);
  for (int i = 0; i < downstream.size(); i++)
    if (downstream[i] == _tcp_a)
      goto found_tcp_a;
  errh->warning("TCPAddressTranslator `%s' is not downstream", _tcp_a->declaration().cc());

 found_tcp_a:
  return 0;
}

void
FTPPortMapper6::uninitialize()
{

}

void
FTPPortMapper6::push(int port, Packet *p)
{
  if (port == 0)
    translate_ipv6_ipv4(p);
  else
    translate_ipv4_ipv6(p);
}

void
FTPPortMapper6::translate_ipv6_ipv4(Packet *p)
{
  //Get pointers to IPv4 header, TCP header and data, offsets and lengths
  const click_ip *iph = p->ip_header();
  const click_tcp *tcph = (click_tcp *)(iph + 1);
  const unsigned char *data = (unsigned char *)tcph + (tcph->th_off<<2);
  unsigned data_offset = (data - p->data());
  unsigned len = (p->data() + p->length()) - data;

  char buf[50];
  unsigned buflen=0;
  int af_number = 0;
  unsigned new_sport = 0;
  int pipe_count = 0;
  int i=0;
  bool command_found = false;

  //Verify that the packet has the right contents
  if (len < 4
      || (data[0] != 'E' && data[0] != 'e')
      || (data[1] != 'P' && data[1] != 'p')
      || (data[2] != 'R' && data[2] != 'r')
      || (data[3] != 'T' && data[3] != 't')
      || data[4] != ' ')
  {
    if (len < 4
      || (data[0] != 'E' && data[0] != 'e')
      || (data[1] != 'P' && data[1] != 'p')
      || (data[2] != 'S' && data[2] != 's')
      || (data[3] != 'V' && data[3] != 'v'))
    {
		  if (len < 3
        || data[0] != '2'
  		  || data[1] != '2'
        || data[2] != '9'
        || data[3] != ' '
        || epsv_found == true)
      {
  		  if (len < 3
          || data[0] != '2'
  	  	  || data[1] != '0'
          || data[2] != '0'
          || data[3] != ' ')
        {
          output(0).push(p);
          return;
        }
        else
        {
          command_found = true;
        }
        
      }
      else
      {
        command_found = true;
      }
    }
    else
    {
      command_found = true;
    }
  }
  else
  {
    command_found = true;
  }
  if (command_found == true)
  {
     // parse the EPRT/EPSV commands
    //unsigned pos = 5;
    unsigned pos = 4;
    while (pos < len && data[pos] == ' ')
      pos++;
    unsigned port_arg_offset = pos;

    if ((data[0] == 'E' || data[0] == 'e')
      && (data[1] == 'P' || data[1] == 'p')
      && (data[2] == 'S' || data[2] == 's')
      && (data[3] == 'V' || data[3] == 'v'))
    {
      buflen = sprintf(buf, "PASV\r\n");

    }
    else if ((data[0] == 'E' || data[0] == 'e')
      && (data[1] == 'P' || data[1] == 'p')
      && (data[2] == 'R' || data[2] == 'r')
      && (data[3] == 'T' || data[3] == 't')
      && data[4] == ' ')
    {
      //Parse the EPRT command, get AF number and port, the IPv6 address in the command doesn't matter,
      //the one we need is the packet's source address.
      while (pos < len && pipe_count < 4)
      {
        if (i == 1)
          af_number = data[pos] - '0';
        else if (pipe_count == 3 && data[pos] != '|')
          new_sport = (new_sport * 10) + data[pos] - '0';
        else if (data[pos] == '|')
            pipe_count++;
        pos++;
        i++;
      }

        //Verify port and AF number are OK
      if ((af_number != 2) || (new_sport < 1024 || new_sport > 65536)
        || pos >= len || (data[pos] != '\r' && data[pos] != '\n')){
          click_chatter("Invalid packet!')");
          output(0).push(p);  
        }
       else
       {
          //get IPv4 source address from header and build new PORT command
          unsigned new_saddr = ntohl(iph->ip_src.s_addr);
          buflen = sprintf(buf, "PORT %d,%d,%d,%d,%d,%d\r\n",(new_saddr>>24)&255, (new_saddr>>16)&255,
	            (new_saddr>>8)&255, new_saddr&255, (new_sport>>8)&255, new_sport&255);
        }
    }
    //Translate EPSV response into a valid PASV one:
    else if((data[0] == '2'
      && data[1] == '2'
      && data[2] == '9'
      && data[3] == ' ') && epsv_found == false)
    {
      while (pos < len && data[pos] != '(')
        pos++;
      port_arg_offset = pos;
      while (pos < len && pipe_count < 4)
      {
        if (pipe_count == 3 && data[pos] != '|')
          new_sport = (new_sport * 10) + data[pos] - '0';
        else if (data[pos] == '|')
          pipe_count++;
        pos++;
      }
      unsigned new_saddr = ntohl(iph->ip_src.s_addr);

      buflen = sprintf(buf, "227 Entering Passive Mode. %d,%d,%d,%d,%d,%d\r\n", (new_saddr>>24)&255,
            (new_saddr>>16)&255,(new_saddr>>8)&255, new_saddr&255, (new_sport>>8)&255, new_sport&255);
    }
    //Translate EPRT response into a valid PORT one:
    else if(data[0] == '2'
      && data[1] == '0'
      && data[2] == '0')
    {

      buflen = sprintf(buf, "200 PORT command successful.\r\n");
    }

    WritablePacket *wp = NULL;
    unsigned newlen = strlen(buf);

    if (len <= newlen)
      wp = p->put(newlen - len);
    else
    {
      wp = p->uniqueify();
      wp->take(len - newlen);
   }

   memmove(wp->data() + data_offset + newlen,
            wp->data() + data_offset + len,
            len - pos);
   memcpy(wp->data() + data_offset,
	         buf,
           newlen);

  // set IP length field, incrementally update IP checksum according to RFC1624
    // new_sum = ~(~old_sum + ~old_halfword + new_halfword)
  click_ip *wp_iph = wp->ip_header();
  unsigned short old_ip_hw = ((unsigned short *)wp_iph)[1];
  wp_iph->ip_len = htons(wp->length() - wp->ip_header_offset());
   unsigned short new_ip_hw = ((unsigned short *)wp_iph)[1];
   unsigned ip_sum =
      (~wp_iph->ip_sum & 0xFFFF) + (~old_ip_hw & 0xFFFF) + new_ip_hw;
  while (ip_sum >> 16)		// XXX necessary?
    ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
  wp_iph->ip_sum = ~ip_sum;

    // set TCP checksum
    // XXX should check old TCP checksum first!!!
    click_tcp *wp_tcph = wp->tcp_header();

    IPAddress ip_src = IPAddress(wp_iph->ip_src);
    IPAddress ip_dst = IPAddress(wp_iph->ip_dst);

    unsigned  short ssport = tcph->th_sport;
    unsigned  short ddport = tcph->th_dport;

    //IP6FlowID p_flow(p);
    if (TCPAddressTranslator::Mapping6 *p_mapping = _tcp_a->get_mapping6(IP_PROTO_TCP, ip_src, ssport, ip_dst, ddport)) {
      tcp_seq_t interesting_seqno = ntohl(wp_tcph->th_seq) + +len;
      p_mapping->update_seqno_delta(interesting_seqno, newlen - len);
    }
    else
    {
			if (TCPAddressTranslator::Mapping6 *p_mapping = _tcp_a->apply_create(ip_src, ssport, ip_dst, ddport))
			{
				tcp_seq_t interesting_seqno = ntohl(wp_tcph->th_seq) + +len;
				p_mapping->update_seqno_delta(interesting_seqno, newlen - len);
			}    	
  	}
    // always update sequence number in this packet so TCPAddressTranslator will fix it
    // (works even with retransmits)
    wp_tcph->th_sum = 0;
    unsigned wp_tcp_len = wp->length() - wp->transport_header_offset();
    unsigned csum = ~click_in_cksum((unsigned char *)wp_tcph, wp_tcp_len) & 0xFFFF;
    #ifdef CLICK_LINUXMODULE
    csum = csum_tcpudp_magic(wp_iph->ip_src.s_addr, wp_iph->ip_dst.s_addr,
		  	   wp_tcp_len, IP_PROTO_TCP, csum);
    #else
    {
      unsigned short *words = (unsigned short *)&wp_iph->ip_src;
      csum += words[0];
      csum += words[1];
      csum += words[2];
      csum += words[3];
      csum += htons(IP_PROTO_TCP);
      csum += htons(wp_tcp_len);
      while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
      csum = ~csum & 0xFFFF;
    }
    #endif
    wp_tcph->th_sum = csum;
    output(0).push(wp);
  }
}

void
FTPPortMapper6::translate_ipv4_ipv6(Packet *p)
{

  click_ip6 *ip6 = (click_ip6 *)p->data();
  IP6Address ip6_src = IP6Address(ip6->ip6_src);
  const click_tcp *tcph = (click_tcp *)(ip6 + 1);
  const unsigned char *data = (unsigned char *)tcph + (tcph->th_off<<2);
  unsigned len = (p->data() + p->length()) - data;
  unsigned data_offset = (data - p->data());


  char buf[100];
  unsigned buflen=0;
  int comma_count = 0;
  int new_sport = 0;
  int i = 0;
  bool command_found = false;

  if (len < 4
    || (data[0] != 'P' && data[0] != 'p')
    || (data[1] != 'O' && data[1] != 'o')
    || (data[2] != 'R' && data[2] != 'r')
    || (data[3] != 'T' && data[3] != 't')
    || data[4] != ' ')
  {
    if (len < 4
      || (data[0] != 'P' && data[0] != 'p')
      || (data[1] != 'A' && data[1] != 'a')
      || (data[2] != 'S' && data[2] != 's')
      || (data[3] != 'V' && data[3] != 'v'))
    {
  		if (len < 3
        || data[0] != '2'
		    || data[1] != '2'
        || data[2] != '7'
        || data[3] != ' ')
      {
    		if (len < 3
            || data[0] != '2'
		        || data[1] != '0'
            || data[2] != '0'
            || data[3] != ' ')
        {
          output(1).push(p);
        }
        else
        {
          command_found = true;
        }        
      }
      else
      {
        command_found = true;
      }
    }
    else
    {
      command_found = true;
    }
  }
  else
  {
    command_found = true;
  }

  if (command_found == true)
  {

     // parse the PORT/PASV commands
    //unsigned pos = 5;
    unsigned pos = 4;
    while (pos < len && data[pos] == ' ')
      pos++;
    unsigned port_arg_offset = pos;

    if ((data[0] == 'P' || data[0] == 'p')
      && (data[1] == 'A' || data[1] == 'a')
      && (data[2] == 'S' || data[2] == 's')
      && (data[3] == 'V' || data[3] == 'v'))
    {
      buflen = sprintf(buf, "EPSV\r\n");
      epsv_found = false;

    }

    else if ((data[0] == 'P' || data[0] == 'p')
      && (data[1] == 'O' || data[1] == 'o')
      && (data[2] == 'R' || data[2] == 'r')
      && (data[3] == 'T' || data[3] == 't')
      && data[4] == ' ')
    {
      // followed by 6 decimal numbers separated by commas
      unsigned nums[6];
      nums[0] = nums[1] = nums[2] = nums[3] = nums[4] = nums[5] = 0;
      int which_num = 0;

      while (pos < len && which_num < 6)
      {
          if (data[pos] >= '0' && data[pos] <= '9')
              nums[which_num] = (nums[which_num] * 10) + data[pos] - '0';
          else if (data[pos] == ',')
              which_num++;
          else
              break;
              pos++;
      }

      // check that the command was complete and the numbers are ok
      if (which_num != 5 || pos >= len || (data[pos] != '\r' && data[pos] != '\n')){
          click_chatter("invalid packet!");
          output(1).push(p);
          }
      for (i = 0; i < 6; i++)
          if (nums[i] >= 256)
              output(1).push(p);

     //Get the string representation of the IPv6 address
      String new_saddr=ip6_src.unparse().cc();
      char *s= buf;

     //Build the ERPT command
      buflen= sprintf(s,"EPRT |2|");
      s +=buflen;

      buflen = sprintf (s,"%s|",new_saddr.c_str());
      s += buflen;
      new_sport= (nums[4]<<8)|nums[5];

      buflen = sprintf (s,"%d|\n",new_sport);
    }
    else if(data[0] == '2'
	  	&& data[1] == '2'
      && data[2] == '7'
      && data[3] == ' ')
    {
      unsigned p1 = 0;
      unsigned p2 = 0;
      while (pos < len && data[pos] == ' ')
        pos++;
      port_arg_offset = pos;
      while (pos < len && comma_count <= 5)
      {
        if (comma_count == 4 && data[pos] != ',')
          p1 = (p1 * 10) + data[pos] - '0';
        else if (comma_count == 5 && data[pos] != ')' && data[pos] != '\r' && data[pos] != '\n'){
          p2 = (p2 * 10) + data[pos] - '0';
        }
        else if (data[pos] == ',')
          comma_count++;
        else if (data[pos] == ')')
          break;
        pos++;
      }
      new_sport = (p1<<8)|p2;

      buflen = sprintf(buf, "229 Entering Extended Passive mode (|||%d|)\r\n",new_sport);

    }
    //Translate EPRT response into a valid PORT one:
    else if(data[0] == '2'
      && data[1] == '0'
      && data[2] == '0'
      && data[3] == ' ')
    {
      buflen = sprintf(buf, "200 EPRT command successful.\r\n");
    }

      WritablePacket *wp;
      unsigned newlen = strlen(buf);

      if (len <= newlen){
        wp = p->put(newlen - len);
        }
      else
      {
        wp = p->uniqueify();
        wp->take(len - newlen);
      }
      memmove(wp->data() + data_offset + newlen,
              wp->data() + data_offset + len,
	            len - pos);
      memcpy(wp->data() + data_offset,
	           buf,
             newlen);
      click_ip6 *wp_ip6h = (click_ip6 *)wp->data();
      //update payload length of IPv6 header
      wp_ip6h->ip6_plen = htons(wp->length() - wp->ip6_header_length());
    // set TCP checksum
      click_tcp *wp_tcph = (click_tcp *)(wp_ip6h + 1);
	  //but first update deltas for seq and ack numbers so TCPAddressTranslator can update the seq and ack numbers.
      IP6FlowID p_flow(p);

      if (TCPAddressTranslator::Mapping6 *p_mapping = _tcp_a->get_mapping6(IP_PROTO_TCP, p_flow)) {
        tcp_seq_t interesting_seqno = ntohl(wp_tcph->th_seq) + +len;
        p_mapping->update_seqno_delta(interesting_seqno, newlen -len);
      }
      else if (TCPAddressTranslator::Mapping6 *p_mapping = _tcp_a->apply_create(0,p_flow))
			{
        tcp_seq_t interesting_seqno = ntohl(wp_tcph->th_seq) + +len;
	  		p_mapping->update_seqno_delta(interesting_seqno, newlen - len);				
		  }
    	
      unsigned char *start_of_p = (unsigned char *)(wp_ip6h+1);
      wp_tcph->th_sum = htons(in6_fast_cksum(&wp_ip6h->ip6_src,
                                            &wp_ip6h->ip6_dst,
                                            wp_ip6h->ip6_plen,
                                            wp_ip6h->ip6_nxt,
                                            wp_tcph->th_sum,
                                            start_of_p,
                                            wp_ip6h->ip6_plen));

      output(1).push(wp);
    }
}
CLICK_ENDDECLS
ELEMENT_REQUIRES(TCPAddressTranslator)
EXPORT_ELEMENT(FTPPortMapper6)
