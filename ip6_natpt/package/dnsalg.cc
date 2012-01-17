/*
 * dnsalg.{cc,hh}
 * Application Level Gateway that translates DNS queries
 * in IPv4/IPv6 packets, as a complement to the NAT-PT
 * elements of Click (AddressTranslator, ProtocolTranslator64
 * and ProtocolTranslator46).
 *
 * Juan Luis Baptiste <juancho@linuxmail.org>
 * Bogota - Colombia 2002 - 2003.
 *
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#include "dnsalg.hh"

CLICK_DECLS


DNSAlg::DNSAlg()
{
    /* in 0: IPv4 arriving packets */
    /* in 1: IPv6 arriving packets */
    /* out 0: IPv4 outgoing translated packets*/
    /* out 1: IPv6 outgoing translated packets*/
}

DNSAlg::~DNSAlg()
{
}

int
DNSAlg::configure(Vector<String> &conf, ErrorHandler *errh)
{
  String rest;
  if (conf.size() != 5)
    return errh->error("Wrong number of arguments; expected `DnsAlg(AddressTranlator, PTR zone IPv4 network, IPv4 DNS server name, PTR zone IPv6 network, IPv6 DNS server name)'");

  // get control packet rewriter
  Element *e = cp_element(conf[0], this, errh);
  if (!e)
    return -1;
  _at = (AddressTranslator *)e->cast("AddressTranslator");
  if (!_at)
    return errh->error("First argument must be a AddressTranslator element");
  if (!cp_string(conf[1],&ipv4_dns_server_ptr_domain,&rest))
    return errh->error("Second parameter must be the PTR domain zone of the IPv4 Network");
  if (!cp_string(conf[2],&ipv4_dns_server_name,&rest))
    return errh->error("Third parameter must be the name of the DNS server of the IPv4 Network");  
  if (!cp_string(conf[3],&ipv6_dns_server_ptr_domain,&rest))
    return errh->error("Four parameter must be the PTR domain zone of the IPv6 Network");
  if (!cp_string(conf[4],&ipv6_dns_server_name,&rest))
    return errh->error("Fifth parameter must be the name of the DNS server of the IPv6 Network");
   
  return 0;
}

int
DNSAlg::initialize(ErrorHandler *errh)
{
  return 0;
}

void
DNSAlg::uninitialize()
{

}

void
DNSAlg::push(int port, Packet *p)
{
  if (port == 0)
    translate_ipv6_ipv4(p);
  else
    translate_ipv4_ipv6(p);
}

void
DNSAlg::translate_ipv4_ipv6(Packet *p)
{
  //Get pointers to IPv4 header, TCP header and data, offsets and lengths
  const click_ip6 *ip6h = p->ip6_header();
  const click_udp *udph = (click_udp *)(ip6h + 1);
  const unsigned char *data = (unsigned char *)(udph + 1);

  unsigned len = 0;
  //size of the packets data, no tcp/udp/IPv6 headers included
  len = ntohs(ip6h->ip6_plen) - sizeof(click_udp);
  unsigned old_len = len;
  unsigned data_offset = (data - p->data());
  unsigned short qtype;
  unsigned short qclass;
  unsigned short sport,dport,mport;
  unsigned usport = ntohs(udph->uh_sport);
  unsigned udport = ntohs(udph->uh_dport);
  unsigned newlen = 0;
  size_t new_len = 1024;
  int i=0;
  off_t off = 0;
  rfc1035_header hdr;
  const char *buffer;
  const char *domainName = new char[1024];
  char *newbuffer = new char[1024];
  IP6Address ipv6_internal_address;
  IP6Address ipv6_mapped_address;
  IP6Address ipv6_external_address = IP6Address(ip6h->ip6_src);

  buffer = (const char*)data;
  DNSMessage *dnsmsg = new DNSMessage();
  memset(&hdr, '\0', sizeof(hdr));

  //Unpack DNS header and see if it is a query or response
  if ((dnsmsg->rfc1035HeaderUnpack(buffer,len,&off,&hdr) == 1) || (usport != 53 && udport != 53))
  {
    //If it is not a DNS query, send the packet with no modification.
    output(1).push(p);
    return;
  }
  else if (len == off)
  {
    output(1).push(p);
    return;

  }  
  else
  {
    memset(newbuffer, '\0', len);
    //it's a question
    if (hdr.qr == 0)
    {
      //Now we have to extract the QTYPE and QCLASS of the question
      //For this we have to calculate the offset of where those values begins.
      //So we first unpack the name of the question so we can now know where QTYPE starts
      if (dnsmsg->rfc1035NameUnpack(buffer, len, &off,(char *)domainName, RFC1035_MAXHOSTNAMESZ))
      {
        click_chatter("ERROR obtaining domaine name (4->6)");
        return;
      }
      else
      {
        memcpy(&qtype, buffer + off, sizeof(qtype));
        off += sizeof(qtype);
        qtype = ntohs(qtype);
        memcpy(&qclass, buffer + off, sizeof(qclass));
        off += sizeof(qclass);
        qclass = ntohs(qclass);
        if (qtype == RFC1035_TYPE_A)
        {
          dnsmsg->rfc1035BuildAAAAQuery(domainName, newbuffer, &new_len, hdr.id);
          //After building the query, len has the size of the new AAAA Query.
        }
        else if (qtype == RFC1035_TYPE_AAAA)
        {
          click_chatter("Found AAAA query generated from IPv4...");
          return;
        }
        else if (qtype == RFC1035_TYPE_PTR)
        {
          //get the IPv4 address contained in the inverse query
          char *ipv4_address = new char[RFC1035_MAXHOSTNAMESZ];
	 memset(ipv4_address,'\0',RFC1035_MAXHOSTNAMESZ); 
          if (get_query_ipv4_address(domainName, ipv4_address) == 0)
          {
            click_chatter("Error: get_query_ipv4_address (4->6)");
            return;
          }
          char *ipv6_address = new char[RFC1035_MAXHOSTNAMESZ];
	      memset(ipv6_address,'\0',RFC1035_MAXHOSTNAMESZ);
          sprintf(ipv6_address,"::%s",ipv4_address);
	      ipv6_mapped_address = IP6Address(ipv6_address);

          //Lookup its original IPv6 address in the Address Translator
          if (_at->lookup(ipv6_internal_address, sport, ipv6_mapped_address, mport, ipv6_external_address, dport, 1))
          {
            //If found, create new PTR query with the mapped IPv4 address
            char *new_ipv6_internal_address = dnsmsg->my_strdup(ipv6_internal_address.unparse().c_str());
            dnsmsg->rfc1035BuildPTR6Query(new_ipv6_internal_address,newbuffer, &new_len, hdr.id);
            delete (ipv4_address);
            delete (ipv6_address);
            delete (new_ipv6_internal_address);            
          }
          else
          {
            //We can't find a IPv6 address for the mapped IPv4 address the client is querying, so we answer to him
            //with a SERVER FAILED response.
            click_chatter("LOOKUP FAILED: No IPv6 address asociated with that IP address and cannot associate one to it!");
            dnsmsg->rfc1035BuildFailedQueryResponse(domainName,qtype,newbuffer, &new_len, hdr.id);
            failed_query = true;
          }
        }
      }
      newlen = new_len;
      delete (domainName);
    }
    else if (hdr.qr == 1)//it's an answer
    {
      unsigned short rid;
      int n;
      off_t off2 = 0;
      char *ipv6_ptr_domain = new char[RFC1035_MAXHOSTNAMESZ];
      memset(ipv6_ptr_domain,'\0',RFC1035_MAXHOSTNAMESZ);
      struct in_addr ipv4_addr_from_AAAA_answer;

      //First pack the header section because it doesn't need any type of
      //translation.
      off2 += dnsmsg->rfc1035HeaderPack(newbuffer, new_len, &hdr);
      new_len -= off2;
      //Unpack again the question, because in the answers, the question in the message also
      //needs to be translated.
      if (dnsmsg->rfc1035NameUnpack(buffer, len, &off, (char *)domainName, RFC1035_MAXHOSTNAMESZ))
      {
        click_chatter("Failed domain Name unpacking...(4->6)");
        return;
      }
      else
      {
        memcpy(&qtype, buffer + off, sizeof(qtype));
        off += sizeof(qtype);
        qtype = ntohs(qtype);
        memcpy(&qclass, buffer + off, sizeof(qclass));
        off += sizeof(qclass);
        qclass = ntohs(qclass);

        //First, we update the question section
        if (qtype == RFC1035_TYPE_A)
        {
          off2 += dnsmsg->rfc1035QuestionPack(newbuffer + off2, new_len - off2, domainName, RFC1035_TYPE_AAAA, qclass);
          new_len -= off2;
        }
        else if (qtype == RFC1035_TYPE_PTR)
        {
          char *ipv4_address = new char[16];
          memset(ipv4_address,'\0',16);
	      int nn = get_query_ipv4_address(domainName, ipv4_address);
          if (nn == 0)
          {
            return;
          }
          else
          {
            char *ipv6_address = new char[RFC1035_MAXHOSTNAMESZ];
            memset(ipv6_address,'\0',RFC1035_MAXHOSTNAMESZ);
            sprintf(ipv6_address,"::%s",ipv4_address);
	        ipv6_ptr_domain = dnsmsg->rfc1035BuildPTR6Domain(ipv6_address);
            off2 += dnsmsg->rfc1035QuestionPack(newbuffer + off2, new_len - off2, ipv6_ptr_domain, RFC1035_TYPE_PTR, qclass);
            new_len -= off2;
            delete(ipv4_address);
          }
        }
        off_t offset_after_answers = 0;
        rfc1035_rr *answers = NULL;
        rfc1035_rr *authorities = NULL;
        rfc1035_rr *additionals = NULL;
        n = dnsmsg->rfc1035AnswersUnpack(buffer,len,&answers, &authorities, &additionals, &rid,&offset_after_answers);        
        if (n == -2) //Server Failure: The name server was unable to process this query (didn't found an answer :-( ).
          n = 0;
  	    if (n < 0)
        {
          click_chatter("Bad response from DNS server! (4->6)");
          //It's a corrupt answer
          return;
  	    }
        for (i = 0; i < n; i++)
        {
	    	  if (answers[i].type == RFC1035_TYPE_A)
          {
            //First, we update the question section
            //Then we translate the answer
            answers[i].type = RFC1035_TYPE_AAAA;
            struct in_addr a;
         		memcpy(&a, answers[i].rdata, 4);
            char *ipv6_address = new char[RFC1035_MAXHOSTNAMESZ];
            //Create a IPAddress instance, and then create a IP6Address instance to create
            //the IPv4-mapped IPv6 address
            IPAddress tempaddr = IPAddress(a);
            IP6Address temp6 = IP6Address(tempaddr);
            click_in6_addr ipv6_addr;            
            ipv6_addr = temp6.in6_addr();
            delete (answers[i].rdata);            
            answers[i].rdlength = sizeof(struct in6_addr);
            answers[i].rdata = new char[answers[i].rdlength];
            memset(answers[i].rdata,'\0',answers[i].rdlength);
            memcpy(answers[i].rdata,&ipv6_addr,answers[i].rdlength);
            dnsmsg->rfc1035RRPack(&answers[i],&off2,newbuffer,new_len);
            new_len -= off2;
            delete (ipv6_address);
          }
          else if (answers[i].type == RFC1035_TYPE_PTR)
          {
            memset(answers[i].name,'\0',RFC1035_MAXHOSTNAMESZ);
            memcpy(answers[i].name,ipv6_ptr_domain,strlen(ipv6_ptr_domain));
            dnsmsg->rfc1035RRPack(&answers[i],&off2,newbuffer,new_len);
            new_len -= off2;
          } 
        }
       //Now we need to translate the Autorities and Aditionals sections (if needed)
        for (i = 0; i < hdr.nscount; i++)
        {
          if (qtype == RFC1035_TYPE_PTR)
          {
            memset(authorities[i].name,'\0',RFC1035_MAXHOSTNAMESZ);            
            memcpy(authorities[i].name,ipv6_dns_server_ptr_domain.c_str(),strlen(ipv6_dns_server_ptr_domain.c_str()));
          }
          memset(authorities[i].rdata,'\0',RFC1035_MAXHOSTNAMESZ);
          memcpy(authorities[i].rdata,ipv4_dns_server_name.c_str(),strlen(ipv4_dns_server_name.c_str()));
          authorities[i].rdlength = strlen(ipv4_dns_server_name.c_str()) + 2;          
          dnsmsg->rfc1035RRPack(&authorities[i],&off2,newbuffer,new_len);
          new_len -= off2;
        }
        for (i = 0; i < hdr.arcount; i++)
        {
          //In case that the query was PTR type and there is a AAAA RR in the additionas
          //it has to be translated too.
          if (additionals[i].type == RFC1035_TYPE_A)
          {
            additionals[i].type = RFC1035_TYPE_AAAA;
            struct in_addr a;
         		memcpy(&a, additionals[i].rdata, sizeof(struct in_addr));
            IPAddress tmpaddr = IPAddress(a);
            IP6Address tmpaddr6 = IP6Address(tmpaddr);
            click_in6_addr ipv6_addr;
            ipv6_addr = tmpaddr6.in6_addr();
            delete (additionals[i].rdata);
            additionals[i].rdlength = sizeof(struct in6_addr);            
            additionals[i].rdata = new char[additionals[i].rdlength];
            memset(additionals[i].rdata,'\0',additionals[i].rdlength);
            memcpy(additionals[i].rdata,&ipv6_addr,additionals[i].rdlength);
          }
          
          dnsmsg->rfc1035RRPack(&additionals[i],&off2,newbuffer,new_len);
          new_len -= off2;
        }
      }

      newlen = off2;
      delete (ipv6_ptr_domain);
      delete (domainName);
    }
    WritablePacket *wp;
    if (old_len < newlen)
    {
      wp = p->put(newlen - old_len);
    }
    else
    {
      wp = p->uniqueify();
      wp->take(old_len - newlen);
    }
    memcpy(wp->data() + data_offset,newbuffer,newlen);
    //Delete the temporal newbuffer
    delete(newbuffer);

    click_ip6 *wp_ip6h = (click_ip6 *)wp->data();
    click_udp *wp_udph = (click_udp *)(wp_ip6h + 1);
    if (failed_query)
    {
        IP6Address temp_src = IP6Address(wp_ip6h->ip6_src);
        IP6Address temp_dst = IP6Address(wp_ip6h->ip6_dst);
        unsigned temp_src_port = wp_udph->uh_sport;
        unsigned temp_dst_port = wp_udph->uh_dport;
        
        //We invert addresses so we can send the failed query response to the client
        wp_ip6h->ip6_src = temp_dst.in6_addr();
        wp_ip6h->ip6_dst = temp_src.in6_addr();
        wp_udph->uh_sport = temp_dst_port;
        wp_udph->uh_dport = temp_src_port;        
        failed_query = false;        
    }
    else    
    //update payload length of IPv6 header
    wp_ip6h->ip6_plen = htons(wp->length() - wp->ip6_header_length());
    //update UDP checksum
    wp_udph->uh_ulen = htons(newlen + sizeof(click_udp));
    wp_udph->uh_sum = htons(in6_fast_cksum(&wp_ip6h->ip6_src, &wp_ip6h->ip6_dst,
                                            wp_ip6h->ip6_plen, wp_ip6h->ip6_nxt,
                                            wp_udph->uh_sum, (unsigned char *)wp_udph,
                                            wp_ip6h->ip6_plen));
    
    output(1).push(wp);
  }
}
void
DNSAlg::translate_ipv6_ipv4(Packet *p)
{
  const click_ip *iph = p->ip_header();
  const click_udp *udph = p->udp_header();
  const unsigned char *data = (unsigned char *)(udph + 1);
  unsigned data_offset = (data - p->data());
  unsigned len = ntohs(iph->ip_len) - sizeof(click_ip) - sizeof(click_udp);
  unsigned old_len = len;
  unsigned short sport,dport,mport;
  unsigned short usport = ntohs(udph->uh_sport);
  unsigned short udport = ntohs(udph->uh_dport);
  unsigned short qtype;
  unsigned short qclass;  
  int i = 0;
  off_t off = 0;  
  IP6Address ipv6_internal_address;
  IP6Address ipv6_mapped_address;
  IP6Address ipv6_external_address = IP6Address(iph->ip_dst);
  rfc1035_header hdr;
  const char *buffer;
  const char * domainName = new char[1024];
  //new buffer of the same size of the actual buffer
  char *newbuffer = new char[1024];
  unsigned newlen = 0;
  size_t new_len = 1024;

  buffer = (const char*)data;
  DNSMessage *dnsmsg = new DNSMessage();
  memset(&hdr, '\0', sizeof(hdr));
  //Unpack DNS header and see if it is a query or response
  if ((dnsmsg->rfc1035HeaderUnpack(buffer,len,&off,&hdr) == 1) || (usport != 53 && udport != 53))
  {
    //If it is a bogus query, send the packet with no modification.
    output(0).push(p);
  }
  else if (len == off)
  {
    output(0).push(p);
    return;

  } 
  else
  {
    //it's a question
    if (hdr.qr == 0)
    {
      //Now we have to extract the QTYPE and QCLASS of the question
      //For this we have to calculate the offset of where those values begins.
      //So we first unpack the name of the question so we can now know where QTYPE starts
      if (dnsmsg->rfc1035NameUnpack(buffer,len,&off,(char *)domainName,RFC1035_MAXHOSTNAMESZ))
      {
        click_chatter("Error obtaining Domain Name...(6->4)");
        return;
      }
      else
      {
        memcpy(&qtype, buffer + off, sizeof(qtype));
        off += sizeof(qtype);
        qtype = ntohs(qtype);
        memcpy(&qclass, buffer + off, sizeof(qclass));
        off += sizeof(qclass);
        qclass = ntohs(qclass);
        memset(newbuffer, '\0', len);
        if (qtype == RFC1035_TYPE_AAAA)
        {
          dnsmsg->rfc1035BuildAQuery(domainName,newbuffer,&new_len, hdr.id);

          //After building the query, len has the size of the new A Query.
        }
        else if (qtype == RFC1035_TYPE_A)
        {
          return;
        } 

        else if (qtype == RFC1035_TYPE_PTR)
        {
          //get the IPv6 address contained in the inverse query
          char *ipv6_address = new char[RFC1035_MAXHOSTNAMESZ];
					memset(ipv6_address,'\0',RFC1035_MAXHOSTNAMESZ);
          if (get_query_ipv6_address(domainName, ipv6_address) == 0)
          {
            return;
          }
          else
          {
            int ipv4_addr[4];
            hex_ipv4_to_dec_ipv4(ipv6_address,ipv4_addr);

            char *addr_tmp = new char[RFC1035_MAXHOSTNAMESZ];
            //snprintf(addr_tmp,16,"%d.%d.%d.%d",ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
      	    sprintf(addr_tmp,"%d.%d.%d.%d",ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);	
            struct in_addr ipv4_a;
            IPAddress tempaddr = IPAddress(addr_tmp);
            ipv4_a = tempaddr.in_addr();
            dnsmsg->rfc1035BuildPTRQuery(ipv4_a,newbuffer, &new_len, hdr.id);
            delete (ipv6_address);
            delete (addr_tmp);
          }  
        }
      }
      newlen = new_len;
      delete (domainName);
    }
    else if (hdr.qr == 1)//it's an answer
    {
      unsigned short rid;
      int n;
      off_t off2 = 0;
      char *ipv4_ptr_domain = new char[RFC1035_MAXHOSTNAMESZ];
      memset(ipv4_ptr_domain,'\0',RFC1035_MAXHOSTNAMESZ);
      struct in_addr ipv4_addr_from_AAAA_answer;

      //First pack the header section because it doesn't need any type of
      //translation.
      off2 += dnsmsg->rfc1035HeaderPack(newbuffer, new_len, &hdr);
      new_len -= off2;
      //Unpack again the question, because in the answers, the question in the message also
      //needs to be translated.
      if (dnsmsg->rfc1035NameUnpack(buffer, len, &off, (char *)domainName, RFC1035_MAXHOSTNAMESZ))
      {
        click_chatter("Failed domain Name unpacking... (6->4)");
        output(0).push(p);        
        return;
      }
      else
      {
        memcpy(&qtype, buffer + off, sizeof(qtype));
        off += sizeof(qtype);
        qtype = ntohs(qtype);
        memcpy(&qclass, buffer + off, sizeof(qclass));
        off += sizeof(qclass);
        qclass = ntohs(qclass);

        //First, we update the question section        
        if (qtype == RFC1035_TYPE_AAAA)
        {
          off2 += dnsmsg->rfc1035QuestionPack(newbuffer + off2, new_len - off2, domainName, RFC1035_TYPE_A, qclass);                      
          new_len -= off2;
        }
        else if (qtype == RFC1035_TYPE_PTR)
        {
          char *ipv6_address = new char[RFC1035_MAXHOSTNAMESZ];
          memset(ipv6_address,'\0',RFC1035_MAXHOSTNAMESZ);
          if (get_query_ipv6_address(domainName, ipv6_address) == 0)
          {
            output(0).push(p);
            return;
          }
          else
            ipv6_internal_address = IP6Address(ipv6_address);
          //Lookup its original IPv6 address in the Address Translator
          if (_at->lookup(ipv6_internal_address,sport,ipv6_mapped_address,mport,ipv6_external_address,dport, 0))
          {
            char *new_ipv6_mapped_address = dnsmsg->my_strdup(ipv6_mapped_address.unparse().c_str());
            char *new_ipv4_address = new char[RFC1035_MAXHOSTNAMESZ];
            memset(new_ipv4_address, '\0', RFC1035_MAXHOSTNAMESZ);
            if (extract_ipv4_address_from_ipv6_address(new_ipv6_mapped_address,new_ipv4_address) == 0)
            {
              click_chatter("There was a problem getting the IPv4 address from the IPv4-compatible IPv6 address returned by AddressTranslator!");
              return;
            }            
            struct in_addr ipv4_addr;
            IPAddress tempaddr = IPAddress(new_ipv4_address);
            ipv4_addr = tempaddr.in_addr();
            make_ipv4_ptr_domain(ipv4_addr, ipv4_ptr_domain);
            delete (ipv6_address);
            delete (new_ipv6_mapped_address);
            delete (new_ipv4_address);
          }
          else
          {
            click_chatter("Lookup failed (6->4)");
            return;
          }
          off2 += dnsmsg->rfc1035QuestionPack(newbuffer + off2, new_len - off2, ipv4_ptr_domain, RFC1035_TYPE_PTR, qclass);
          new_len -= off2;
        }

        off_t offset_after_answers = 0;
        rfc1035_rr *answers = NULL;
        rfc1035_rr *authorities = NULL;
        rfc1035_rr *additionals = NULL;        
        n = dnsmsg->rfc1035AnswersUnpack(buffer,new_len,&answers, &authorities, &additionals, &rid,&offset_after_answers);
        if (n == -2) //Server Failure: The name server was unable to process this query (didn't found an answer :-( ).
          n = 0;        
  	    if (n < 0)
        {
          click_chatter("Bad response from DNS server! (6->4)");
          //It's a corrupt answer
          return;
  	    }
        
        for (i = 0; i < n; i++)
        {
	    	  if (answers[i].type == RFC1035_TYPE_AAAA)
          {
            //Then we translate the answer
            click_in6_addr ipv6_addr;
       	  	memcpy(&ipv6_addr, answers[i].rdata, answers[i].rdlength);
            ipv6_internal_address = IP6Address(ipv6_addr);

            //Lookup in the Address Translator the mapped IPv4 address for the IPv6 address of the response
            if (_at->lookup(ipv6_internal_address,sport,ipv6_mapped_address,mport,ipv6_external_address,dport, 0))
            {
              char *new_ipv6_mapped_address = dnsmsg->my_strdup(ipv6_mapped_address.unparse().c_str());
              char *new_ipv4_address = new char[RFC1035_MAXHOSTNAMESZ];
              memset(new_ipv4_address, '\0', RFC1035_MAXHOSTNAMESZ);
              if (extract_ipv4_address_from_ipv6_address(new_ipv6_mapped_address,new_ipv4_address) == 0)
              {
                click_chatter("There was a problem getting the IPv4 address from the IPv4-compatible IPv6 address returned by AddressTranslator!");
                return;
              }
              IPAddress tempaddr = IPAddress(new_ipv4_address);
              ipv4_addr_from_AAAA_answer = tempaddr.in_addr();
              answers[i].type = RFC1035_TYPE_A;
              delete(answers[i].rdata);              
              answers[i].rdlength = sizeof(struct in_addr);
              answers[i].rdata = new char[answers[i].rdlength];
              memset(answers[i].rdata,'\0',answers[i].rdlength);
              memcpy(answers[i].rdata,&ipv4_addr_from_AAAA_answer,answers[i].rdlength);
              dnsmsg->rfc1035RRPack(&answers[i],&off2,newbuffer,new_len);
              new_len -= off2;
              delete (new_ipv6_mapped_address);
              delete (new_ipv4_address);
            }
            else
            {
              click_chatter("LOOKUP FAILED! (6->4)");
              return;
            }
          }
          else if (answers[i].type == RFC1035_TYPE_PTR)
          {
            memset(answers[i].name,'\0',RFC1035_MAXHOSTNAMESZ);
            memcpy(answers[i].name,ipv4_ptr_domain,strlen(ipv4_ptr_domain));
            dnsmsg->rfc1035RRPack(&answers[i],&off2,newbuffer,new_len);
            new_len -= off2;            
          }

        }

       //Now we need to copy the Autorities and Aditionals sections                         
        for (i = 0; i < hdr.nscount; i++)
        {
          if (qtype == RFC1035_TYPE_PTR)
          {
            memset(authorities[i].name,'\0',RFC1035_MAXHOSTNAMESZ);
            memcpy(authorities[i].name,ipv4_dns_server_ptr_domain.c_str(),strlen(ipv4_dns_server_ptr_domain.c_str()));
          }
          authorities[i].rdlength = strlen(ipv6_dns_server_name.c_str()) + 2;
          memset(authorities[i].rdata,'\0',RFC1035_MAXHOSTNAMESZ);
          memcpy(authorities[i].rdata,ipv6_dns_server_name.c_str(),strlen(ipv6_dns_server_name.c_str()));          
          dnsmsg->rfc1035RRPack(&authorities[i],&off2,newbuffer,new_len);
          new_len -= off2;
        }

        for (i = 0; i < hdr.arcount; i++)
        {
          //In case that the query was PTR type and there is a AAAA RR in the additionas
          //it has to be translated too.          
          if (additionals[i].type == RFC1035_TYPE_AAAA)
          {
            if (_at->lookup(ipv6_internal_address,sport,ipv6_mapped_address,mport,ipv6_external_address,dport, 0))
            {
              char *new_ipv6_mapped_address = dnsmsg->my_strdup(ipv6_mapped_address.unparse().c_str());
              char *new_ipv4_address = new char[RFC1035_MAXHOSTNAMESZ];
              memset(new_ipv4_address, '\0', RFC1035_MAXHOSTNAMESZ);
              if (extract_ipv4_address_from_ipv6_address(new_ipv6_mapped_address,new_ipv4_address) == 0)
              {
                click_chatter("There was a problem getting the IPv4 address from the IPv4-compatible IPv6 address returned by AddressTranslator!");
                return;
              }
              IPAddress tempaddr = IPAddress(new_ipv4_address);
              ipv4_addr_from_AAAA_answer = tempaddr.in_addr();
              additionals[i].type = RFC1035_TYPE_A;
              delete(additionals[i].rdata);
              additionals[i].rdlength = sizeof(struct in_addr);
              additionals[i].rdata = new char[additionals[i].rdlength];
              memset(additionals[i].rdata,'\0',additionals[i].rdlength);
              memcpy(additionals[i].rdata,&ipv4_addr_from_AAAA_answer,additionals[i].rdlength);
            }
            else
            {
              click_chatter("LOOKUP FAILED! (6->4)");
              return;
            }
          }
          dnsmsg->rfc1035RRPack(&additionals[i],&off2,newbuffer,new_len);          
          new_len -= off2;
        }
      }      
      newlen = off2;
      delete (ipv4_ptr_domain);
      delete (domainName);
    }
    WritablePacket *wp;
    if (old_len < newlen){
      wp = p->put(newlen - old_len);
    }
    else
    {
      wp = p->uniqueify();
      wp->take(old_len - newlen);
    }
    memcpy(wp->data() + data_offset,newbuffer,newlen);

    //Delete the temporal newbuffer
    delete(newbuffer);

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

    // set UDP checksum
    click_udp *wp_udph = (click_udp *)(wp_iph + 1);
           
    unsigned len2 = wp->length() - wp->transport_header_offset();
    wp_udph->uh_ulen = 0;
    wp_udph->uh_ulen = htons(len2);
    
    wp_udph->uh_sum = 0;
    unsigned wp_tcp_len = wp->length() - wp->transport_header_offset();
    unsigned csum = ~click_in_cksum((unsigned char *)wp_udph, wp_tcp_len) & 0xFFFF;
    #ifdef CLICK_LINUXMODULE
    csum = csum_tcpudp_magic(wp_iph->ip_src.s_addr, wp_iph->ip_dst.s_addr,
		  	   wp_tcp_len, IP_PROTO_UDP, csum);
    #else
    {
      unsigned short *words = (unsigned short *)&wp_iph->ip_src;
      csum += words[0];
      csum += words[1];
      csum += words[2];
      csum += words[3];
      csum += htons(IP_PROTO_UDP);
      csum += htons(wp_tcp_len);
      while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
      csum = ~csum & 0xFFFF;
    }
    #endif
    wp_udph->uh_sum = csum;
    
     output(0).push(wp);
  }

}

/**
* Auxiliary functions
**/

/*
* get_query_ipv6_address(const char *ptr_domain, const char *normal_ipv6_address)
*
* Extract the IPv6 address contained in the PTR ip6.int domain
* in ptr_domain and copy it in normal_ipv6_address. Returns the length of the
* IPv6 address in case of success, 0 in failure.
*/

int
DNSAlg::get_query_ipv6_address(const char *ptr_domain, char *normal_ipv6_address)
{
	int i,j,n,cero_flag;
  n = cero_flag = 0;
  if (strstr(ptr_domain,".ip6.int") != NULL)
  {
  	int ipv6_address_length = strlen(ptr_domain) - 8;
//	int ipv6_address_length = RFC1035_MAXHOSTNAMESZ;
    for (i = ipv6_address_length - 1,j = 0; i >= 0; i--, j++)
    {
      if (ptr_domain[i] != '.')
      {
        normal_ipv6_address[j] = ptr_domain[i];
        n++;
      }
      else
        j--;

      if (n == 4 && i > 0)
      {
        j++;
        normal_ipv6_address[j] = ':';
        n = 0;
        cero_flag = 0;
      }
    }   
    return strlen(normal_ipv6_address);
  }
  else
    return 0;
}

/*
* get_query_ipv4_address(const char *ptr_domain, const char *normal_ipv4_address)
*
* Extract the IPv4 address contained in the PTR in-addr.arpa domain
* in ptr_domain and copy it in normal_ipv4_address. Returns the length of the
* IPv4 address in case of success, 0 in failure.
*/

int
DNSAlg::get_query_ipv4_address(const char *ptr_domain, char *normal_ipv4_address)
{
  int ptr_domain_length = strlen(ptr_domain) - 13;
  //int ptr_domain_length = RFC1035_MAXHOSTNAMESZ;
  //char *inverse_ipv4_address = new char[ptr_domain_length];
  char *inverse_ipv4_address = new char[16];
  int i,n;
  int numbers[4];
  n = 0;

  if (strstr(ptr_domain,".in-addr.arpa") != NULL)
  {
    strncpy(inverse_ipv4_address, ptr_domain,ptr_domain_length);
    char * number = strtok(inverse_ipv4_address,".");
    i = 0;
    while(number != NULL)
    {
      numbers[i] = my_atoi(number);
      i++;
      number = strtok(NULL,".");
    }
    //snprintf(normal_ipv4_address,18,"%d.%d.%d.%d",numbers[3],numbers[2],numbers[1],numbers[0]);
 int temp = sprintf(normal_ipv4_address,"%d.%d.%d.%d",numbers[3],numbers[2],numbers[1],numbers[0]); 
delete (inverse_ipv4_address); 
return  temp;
    
  }
  else
    return 0;

}

int
DNSAlg::extract_ipv4_address_from_ipv6_address(const char * new_ipv6_address, char *ipv4_address)
{
//	 char *ipv4_address = new char[strlen(new_ipv6_address) - 1];
//   memset(ipv4_address, '\0', strlen(ipv4_address));
   //Copy a IPv4-compatible IPv6 address like ::1.0.0.1 into 1.0.0.1
   memcpy(ipv4_address,new_ipv6_address + 2,strlen(new_ipv6_address)-2);
   return strlen(ipv4_address);
}

void
DNSAlg::make_ipv4_ptr_domain(struct in_addr addr, char * ptr_domain)
{
  unsigned int i;
  
  i = (unsigned int) ntohl(addr.s_addr);
  /*snprintf(ptr_domain, 32, "%u.%u.%u.%u.in-addr.arpa.",
	        i & 255,
        	(i >> 8) & 255,
        	(i >> 16) & 255,
        	(i >> 24) & 255);
*/
sprintf(ptr_domain, "%u.%u.%u.%u.in-addr.arpa.",
                i & 255,
                (i >> 8) & 255,
                (i >> 16) & 255,
                (i >> 24) & 255);
}
void
DNSAlg::make_ipv4_ptr_domain(int *addr, char * ptr_domain)
{

  /*snprintf(ptr_domain, 32, "%u.%u.%u.%u.in-addr.arpa.",
	        addr[0],
        	addr[1],
        	addr[2],
        	addr[3]);
*/
sprintf(ptr_domain, "%u.%u.%u.%u.in-addr.arpa.",
                addr[0],
                addr[1],
                addr[2],
                addr[3]);
}
void
DNSAlg::hex_ipv4_to_dec_ipv4(char *hex,int *dec)
{
  int conth,contd;
  int mult;
  char *tmp = new char[10];

  memcpy(tmp, hex + strlen(hex) - 10,10);
  mult = 1;
  contd = -1;
  for (conth = 0; tmp[conth]; conth++)
	{
    if (tmp[conth]!= ':')    
		{
      if (mult == 16)
			  mult = 1;
      else
			{
        mult = 16;
        contd++;
        dec[contd] = 0;
      }
	    if (tmp[conth] > '9')
        dec[contd] = dec[contd] + (int(tmp[conth]) - 87)*mult;        
      else
		    dec[contd] = dec[contd] + (int(tmp[conth]) - int('0'))*mult;        
   }
 }
}

int
DNSAlg::my_atoi(const char *string)
{
    int val = 0;

    for (;; string++) {
	switch (*string) {
	    case '0'...'9':
		val = 10*val+(*string -'0');
		break;
	    default:
		return val;
	}
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(AddressTranslator DNSMessage)
EXPORT_ELEMENT(DNSAlg)
