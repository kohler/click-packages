/*
* Implementation of RFC 1035 (DNS).
* Code taken from Squid Proxy Server http://www.squid-cache.org
* By: Duane Wessels
*
* Added DNS IPv6 extensions by: Juan Luis Baptiste <juancho@linuxmail.org>
*
* Distributed under de GNU General Public License (GNU/GPL).
*
*/

#include <click/dnsmessage.hh>


DNSMessage::DNSMessage()
{
}

/*
 * rfc1035HeaderPack()
 *
 * Packs a rfc1035_header structure into a buffer.
 * Returns number of octets packed (should always be 12)
 */
off_t
DNSMessage::rfc1035HeaderPack(char *buf, size_t sz, rfc1035_header * hdr)
{
    off_t off = 0;
    unsigned short s;
    unsigned short t;
    assert(sz >= 12);
    s = htons(hdr->id);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    t = 0;
    t |= hdr->qr << 15;
    t |= (hdr->opcode << 11);
    t |= (hdr->aa << 10);
    t |= (hdr->tc << 9);
    t |= (hdr->rd << 8);
    t |= (hdr->ra << 7);
    t |= hdr->rcode;
    s = htons(t);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->qdcount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->ancount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->nscount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(hdr->arcount);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    assert(off == 12);
    return off;
}

/*
 * rfc1035LabelPack()
 *
 * Packs a label into a buffer.  The format of
 * a label is one octet specifying the number of character
 * bytes to follow.  Labels must be smaller than 64 octets.
 * Returns number of octets packed.
 */
off_t
DNSMessage::rfc1035LabelPack(char *buf, size_t sz, const char *label)
{
    off_t off = 0;
    size_t len = label ? strlen(label) : 0;
    if (label)
	assert(!strchr(label, '.'));
    if (len > RFC1035_MAXLABELSZ)
	len = RFC1035_MAXLABELSZ;
    assert(sz >= len + 1);
    *(buf + off) = (char) len;
    off++;
    memcpy(buf + off, label, len);
    off += len;
    return off;
}

/*
 * rfc1035NamePack()
 *
 * Packs a name into a buffer.  Names are packed as a
 * sequence of labels, terminated with NULL label.
 * Note message compression is not supported here.
 * Returns number of octets packed.
 */
off_t
DNSMessage::rfc1035NamePack(char *buf, size_t sz, const char *name)
{
    off_t off = 0;
    char *copy = DNSMessage::my_strdup(name);
    char *t;
    /*
     * NOTE: use of strtok here makes names like foo....com valid.
     */
    for (t = strtok(copy, "."); t; t = strtok(NULL, "."))
	off += rfc1035LabelPack(buf + off, sz - off, t);
    delete(copy);
    off += rfc1035LabelPack(buf + off, sz - off, NULL);
    assert((unsigned)off <= sz);
    return off;
}

/*
 * rfc1035QuestionPack()
 *
 * Packs a QUESTION section of a message.
 * Returns number of octets packed.
 */
off_t
DNSMessage::rfc1035QuestionPack(char *buf,size_t sz,const char *name,unsigned short type,unsigned short _class)
{
    off_t off = 0;
    unsigned short s;
    off += rfc1035NamePack(buf + off, sz - off, name);
    s = htons(type);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    s = htons(_class);
    memcpy(buf + off, &s, sizeof(s));
    off += sizeof(s);
    assert((unsigned)off <= sz);
    return off;
}

/*
 * rfc1035HeaderUnpack()
 *
 * Unpacks a RFC1035 message header buffer into a rfc1035_header
 * structure.
 *
 * Updates the buffer offset, which is the same as number of
 * octects unpacked since the header starts at offset 0.
 *
 * Returns 0 (success) or 1 (error)
 */
int
DNSMessage::rfc1035HeaderUnpack(const char *buf, size_t sz, off_t * off, rfc1035_header * h)
{
    unsigned short s;
    unsigned short t;
    assert(*off == 0);
    /*
     * The header is 12 octets.  This is a bogus message if the size
     * is less than that.
     */
    if (sz < 12)
	return 1;
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->id = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    t = ntohs(s);
    h->qr = (t >> 15) & 0x01;
    h->opcode = (t >> 11) & 0x0F;
    h->aa = (t >> 10) & 0x01;
    h->tc = (t >> 9) & 0x01;
    h->rd = (t >> 8) & 0x01;
    h->ra = (t >> 7) & 0x01;
    /*
     * We might want to check that the reserved 'Z' bits (6-4) are
     * all zero as per RFC 1035.  If not the message should be
     * rejected.
     */
    h->rcode = t & 0x0F;
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->qdcount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->ancount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->nscount = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    h->arcount = ntohs(s);
    assert((*off) == 12);
    return 0;
}

/*
 * rfc1035NameUnpack()
 *
 * Unpacks a Name in a message buffer into a char*.
 * Note 'buf' points to the beginning of the whole message,
 * 'off' points to the spot where the Name begins, and 'sz'
 * is the size of the whole message.  'name' must be allocated
 * by the caller.
 *
 * Supports the RFC1035 message compression through recursion.
 *
 * Updates the new buffer offset.
 *
 * Returns 0 (success) or 1 (error)
 */
int
DNSMessage::rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, size_t ns)
{
  off_t no = 0;
  unsigned char c;
  size_t len;
  assert(ns > 0);
  do
  {
	  assert((unsigned)(*off) < sz);
  	c = *(buf + (*off));
	  if (c > 191)
    {
	    /* blasted compression */
	    unsigned short s;
	    off_t ptr;
	    memcpy(&s, buf + (*off), sizeof(s));
	    s = ntohs(s);
	    (*off) += sizeof(s);
	    /* Sanity check */
	    if ((unsigned)(*off) >= sz)
		    return 1;
	    ptr = s & 0x3FFF;
	    /* Make sure the pointer is inside this message */
	    if ((unsigned)ptr >= sz)
    		return 1;
	    return rfc1035NameUnpack(buf, sz, &ptr, name + no, ns - no);
	  }
    else if (c > RFC1035_MAXLABELSZ)
    {
	    /*
  	   * "(The 10 and 01 combinations are reserved for future use.)"
	     */
	    return 1;
  	}
    else
    {
	    (*off)++;
	    len = (size_t) c;
  	  if (len == 0)
	  	  break;
	    if (len > (ns - 1))
  		  len = ns - 1;
	    if ((*off) + len > sz)	/* message is too short */
		    return 1;
  	  memcpy(name + no, buf + (*off), len);
	    (*off) += len;
	    no += len;
  	  *(name + (no++)) = '.';
	  }
  } while (c > 0);
  *(name + no - 1) = '\0';
  /* make sure we didn't allow someone to overflow the name buffer */
  assert((unsigned)no <= ns);
  return 0;
}

/*
 * rfc1035RRUnpack()
 *
 * Unpacks a RFC1035 Resource Record into 'RR' from a message buffer.
 * The caller must free RR->rdata!
 *
 * Updates the new message buffer offset.
 *
 * Returns 0 (success) or 1 (error)
 */
int
DNSMessage::rfc1035RRUnpack(const char *buf, size_t sz, off_t * off, rfc1035_rr * RR)
{
    unsigned short s;
    unsigned int i;
    off_t rdata_off;
    if (rfc1035NameUnpack(buf, sz, off, RR->name, RFC1035_MAXHOSTNAMESZ))
    {
	    memset(RR, '\0', sizeof(*RR));
    	return 1;
    }
    /*
     * Make sure the remaining message has enough octets for the
     * rest of the RR fields.
     */
    if ((unsigned)(*off) + 10 > sz)
    {
    	memset(RR, '\0', sizeof(*RR));
    	return 1;
    }
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    RR->type = ntohs(s);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    RR->_class = ntohs(s);
    memcpy(&i, buf + (*off), sizeof(i));
    (*off) += sizeof(i);
    RR->ttl = ntohl(i);
    memcpy(&s, buf + (*off), sizeof(s));
    (*off) += sizeof(s);
    if ((unsigned)(*off) + ntohs(s) > sz)
    {
    	/*
    	 * We got a truncated packet.  'dnscache' truncates UDP
    	 * replies at 512 octets, as per RFC 1035.
    	 */
    	memset(RR, '\0', sizeof(*RR));
    	return 1;
    }
    RR->rdlength = ntohs(s);
//    switch (RR->type)
//    {
//      case RFC1035_TYPE_PTR:
    if (RR->type == RFC1035_TYPE_PTR || RR->type == RFC1035_TYPE_NS)
    {
           RR->rdata = new char[RFC1035_MAXHOSTNAMESZ];
           rdata_off = *off;
           if (rfc1035NameUnpack(buf, sz, &rdata_off, RR->rdata, RFC1035_MAXHOSTNAMESZ))
              return 1;
           if (rdata_off != ((*off) + RR->rdlength))
           {
              /*
        	     * This probably doesn't happen for valid packets, but
        	     * I want to make sure that NameUnpack doesn't go beyond
        	     * the RDATA area.
         	     */
      	      memset(RR, '\0', sizeof(*RR));
        	    return 1;
  	        }
     }
     else
     {      
           RR->rdata = new char[RR->rdlength];
           memcpy(RR->rdata, buf + (*off), RR->rdlength);
     }     
    (*off) += RR->rdlength;
    assert((unsigned)(*off) <= sz);
    return 0;
}


/*
 * rfc1035RRPack()
 *
 * Packs a RFC1035 Resource Record from a 'RR' to a message buffer.
 *
 * Updates the new message buffer offset.
 *
 * Returns 0 (success) or 1 (error)
 */
int
DNSMessage::rfc1035RRPack(rfc1035_rr *RR, off_t * off, char *buf, size_t sz)
{   
    unsigned short s;
    unsigned int i;
    off_t data_off;
    data_off = rfc1035NamePack(buf + (*off), sz,RR->name);   
    (*off) += data_off;
    s = htons(RR->type);
    memcpy(buf + (*off),&s ,sizeof(s));
    (*off) += sizeof(s);

    s = htons(RR->_class);
    memcpy(buf + (*off),&s ,sizeof(s));
    (*off) += sizeof(s);
    
    i = htonl(RR->ttl);
    memcpy(buf + (*off),&i ,sizeof(i));
    (*off) += sizeof(i);

    s = htons(RR->rdlength);
    memcpy(buf + (*off),&s ,sizeof(s));
    (*off) += sizeof(s);
    switch (RR->type)
    {
      case RFC1035_TYPE_PTR:
        if (strlen(RR->rdata) > RFC1035_MAXHOSTNAMESZ)
        {
          return 1;
        }
        data_off = rfc1035NamePack(buf + (*off), sz,RR->rdata);
        (*off) += data_off;
     	  break;
      case RFC1035_TYPE_NS:
        if (strlen(RR->rdata) > RFC1035_MAXHOSTNAMESZ)
        {
          return 1;
        }
        data_off = rfc1035NamePack(buf + (*off), sz,RR->rdata);
        (*off) += data_off;
     	  break;

     default:
        memcpy(buf + (*off),RR->rdata, RR->rdlength);
        (*off) += RR->rdlength;
 	    break;
    }
    
    assert((unsigned)(*off) <= sz);
    return 0;
}


unsigned short
DNSMessage::rfc1035Qid(void)
{
    static unsigned short qid = 0x0001;
    if (++qid == 0xFFFF)
	qid = 0x0001;
    return qid;
}

void
DNSMessage::rfc1035SetErrno(int n)
{
    switch (rfc1035_errno = n) {
    case 0:
	rfc1035_error_message = "No error condition";
	break;
    case 1:
	rfc1035_error_message = "Format Error: The name server was "
	    "unable to interpret the query.";
	break;
    case 2:
	rfc1035_error_message = "Server Failure: The name server was "
	    "unable to process this query.";
	break;
    case 3:
	rfc1035_error_message = "Name Error: The domain name does "
	    "not exist.";
	break;
    case 4:
	rfc1035_error_message = "Not Implemented: The name server does "
	    "not support the requested kind of query.";
	break;
    case 5:
	rfc1035_error_message = "Refused: The name server refuses to "
	    "perform the specified operation.";
	break;
    case rfc1035_unpack_error:
	rfc1035_error_message = "The DNS reply message is corrupt or could "
	    "not be safely parsed.";
	break;
    default:
	rfc1035_error_message = "Unknown Error";
	break;
    }
}

void
DNSMessage::rfc1035RRDestroy(rfc1035_rr * rr, int n)
{
    if (rr == NULL)
	return;
    assert(n > 0);
    while (n--) {
	if (rr[n].rdata)
	    delete(rr[n].rdata);
    }
    delete(rr);
}

/*
 * rfc1035AnswersUnpack()
 *
 * Takes the contents of a DNS reply and fills in an array
 * of resource record structures.  The records array is allocated
 * here, and should be freed by calling rfc1035RRDestroy().
 *
 * Returns number of records unpacked, zero if DNS reply indicates
 * zero answers, or an error number < 0.
 */
int
DNSMessage::rfc1035AnswersUnpack(const char *buf,
    size_t sz,
    rfc1035_rr ** answers,
    rfc1035_rr ** authorities,
    rfc1035_rr ** additionals,    
    unsigned short *id,
    off_t *off)
{
//    off_t off = 0;
    int l;
    int i;
    int n_ans = 0;
    int n_ns = 0;
    int n_ad = 0;    
    rfc1035_header hdr;
    rfc1035_rr *ans;
    rfc1035_rr *auth;
    rfc1035_rr *add;
    
    memset(&hdr, '\0', sizeof(hdr));
    if (DNSMessage::rfc1035HeaderUnpack(buf + (*off), sz - (*off), off, &hdr)) {
    	rfc1035SetErrno(rfc1035_unpack_error);
    	return -rfc1035_unpack_error;
    }
    *id = hdr.id;
    rfc1035_errno = 0;
    rfc1035_error_message = NULL;
    if (hdr.rcode) {
    	rfc1035SetErrno((int) hdr.rcode);
    	return -rfc1035_errno;
    }
    i = (int) hdr.qdcount;
    /* skip question */
    while (i--)
    {
    	do
      {
	      l = (int) (unsigned char) *(buf + (*off));
	      (*off)++;
  	    if (l > 191)
        {	/* compression */
	      	(*off)++;
      		break;
	      }
        else if (l > RFC1035_MAXLABELSZ)
        {
  		/* illegal combination of compression bits */
        		rfc1035SetErrno(rfc1035_unpack_error);
        		return -rfc1035_unpack_error;
	      }
        else
        {
      		(*off) += l;
	      }
  	  } while (l > 0);	/* a zero-length label terminates */
  	  (*off) += 4;		/* qtype, qclass */
      if ((unsigned)(*off) > sz)
      {
	      rfc1035SetErrno(rfc1035_unpack_error);
	      return -rfc1035_unpack_error;
  	  }
    }
    i = (int) hdr.ancount;
    if (i == 0)
  	return 0;
//    ans = (rfc1035_rr *) calloc(i, sizeof(*ans));
    ans = new rfc1035_rr[i];
    while (i--)
    {
	    if ((unsigned)(*off) >= sz)
      {	/* corrupt packet */
	      break;
    	}
	    if (rfc1035RRUnpack(buf, sz, off, &ans[i]))
      {		/* corrupt RR */
	      break;
    	}
	    n_ans++;
    }
    if (n_ans == 0)
    {
	    /*
    	 * we expected to unpack some answers (ancount != 0), but
    	 * didn't actually get any.
    	 */
    	delete(ans);
    	rfc1035SetErrno(rfc1035_unpack_error);
    	return -rfc1035_unpack_error;
    }
    *answers = ans;

    i = (int) hdr.nscount;
    if (i == 0)
    	return n_ans;
//    auth = (rfc1035_rr *) calloc(i, sizeof(*auth));
    auth = new rfc1035_rr[i];
    while (i--)
    {
	    if ((unsigned)(*off) >= sz)
      {	// corrupt packet 
	      break;
    	}
	    if (rfc1035RRUnpack(buf, sz, off, &auth[i]))
      {		// corrupt RR 
	      break;
    	}
	    n_ns++;
    }
    if (n_ns == 0)
    {
    	delete(auth);
    	rfc1035SetErrno(rfc1035_unpack_error);
    	return -rfc1035_unpack_error;
    }
    *authorities = auth;

    i = (int) hdr.arcount;
    if (i == 0)
    	return n_ans;
//    add = (rfc1035_rr *) calloc(i, sizeof(*add));
    add = new rfc1035_rr[i];    
    while (i--)
    {
	    if ((unsigned)(*off) >= sz)
      {	// corrupt packet 
	      break;
    	}
	    if (rfc1035RRUnpack(buf, sz, off, &add[i]))
      {		// corrupt RR 
	      break;
    	}
	    n_ad++;
    }
    if (n_ad == 0)
    {
    	delete(add);
    	rfc1035SetErrno(rfc1035_unpack_error);
    	return -rfc1035_unpack_error;
    }
    *additionals = add;
        
    return n_ans;
}
/*
 * rfc1035BuildAAAAQuery(const char *hostname, char *buf, size_t * szp)
 *
 * Builds a message buffer with a QUESTION to lookup AAAA records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */

unsigned short
DNSMessage::rfc1035BuildAAAAQuery(const char *hostname, char *buf, size_t * szp)
{
  //query id set to 0 so it is auto-generated in the new query.  
  return rfc1035BuildAAAAQuery(hostname, buf, szp, 0);
}
/*
 * rfc1035BuildAAAAQuery(const char *hostname, char *buf, size_t * szp, short qid)
 *
 * Builds a message buffer with a QUESTION to lookup A records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer. On return it contains
 * the size of the message (i.e. how much to write).
 * The 'qid' specifies the query id for this new query, for example,
 * when this new query corresponds to a query translation (from A
 * type to AAAA type). Returns value is the query ID.
 */

unsigned short
DNSMessage::rfc1035BuildAAAAQuery(const char *hostname, char *buf, size_t * szp, unsigned short qid)
{
  static rfc1035_header h;
  off_t offset = 0;
  size_t sz = *szp;
  memset(&h, '\0', sizeof(h));
  /* the first char of hostname must be alphanmeric */
  if (NULL == strchr(Alphanum, *hostname))
  {
	  rfc1035SetErrno(3);
  	return 0;
  }
  
  if (qid > 0)
    h.id = qid;
  else  
    h.id = rfc1035Qid();
    
  h.qr = 0;
  h.rd = 1;
  h.opcode = 0;		/* QUERY */
  h.qdcount = (unsigned int) 1;
  offset = 0;
  offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
  offset += rfc1035QuestionPack(buf + offset, sz - offset,hostname,RFC1035_TYPE_AAAA,RFC1035_CLASS_IN);
  assert((unsigned)offset <= sz);
  *szp = (size_t) offset;
  return h.id;
}

/*
 * rfc1035BuildFailedQueryResponse(const char *hostname, char *buf, size_t * szp, short qid)
 *
 * Builds a message buffer of a failed Query to lookup A/AAAA/PTR records.
 * Caller must allocate 'buf' which should probably be at least 512 octets.
 * The 'szp' initially specifies the size of the buffer. The 'qid' specifies
 * the query id of the query we are  answering. On return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */

unsigned short
DNSMessage::rfc1035BuildFailedQueryResponse(const char *query, int qtype, char *buf, size_t * szp, unsigned short qid)
{
  static rfc1035_header h;
  off_t offset = 0;
  size_t sz = *szp;
  memset(&h, '\0', sizeof(h));
  /* the first char of hostname must be alphanmeric */
  if (NULL == strchr(Alphanum, *query))
  {
	  rfc1035SetErrno(3);
  	return 0;
  }

  h.id = qid;
  h.aa = 0;
  h.qr = 1;
  h.tc= 0;
  h.rd = 1;
  h.ra = 1;
  h.opcode = 0;		/* QUERY */
  h.rcode = 2;
  h.qdcount = (unsigned int) 1;
  offset = 0;
  offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
  offset += rfc1035QuestionPack(buf + offset, sz - offset,query,qtype,RFC1035_CLASS_IN);
  assert((unsigned)offset <= sz);
  *szp = (size_t) offset;
  return h.id;
}


/*
 * rfc1035BuildAQuery(const char *hostname, char *buf, size_t * szp)
 *
 * Builds a message buffer with a QUESTION to lookup A records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */
unsigned short
DNSMessage::rfc1035BuildAQuery(const char *hostname, char *buf, size_t * szp)
{
  //query id set to 0 so it is auto-generated in the new query.  
  return rfc1035BuildAQuery(hostname, buf, szp, 0);
}
/*
 * rfc1035BuildAQuery(const char *hostname, char *buf, size_t * szp, short qid)
 *
 * Builds a message buffer with a QUESTION to lookup A records
 * for a hostname.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer. The 'qid' specifies the query id for this
 * new query, for example, when this new query corresponds to a query
 * translation (from AAAA type to A type). On return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */
unsigned short
DNSMessage::rfc1035BuildAQuery(const char *hostname, char *buf, size_t * szp, unsigned short qid)
{
  static rfc1035_header h;
  off_t offset = 0;
  size_t sz = *szp;
  memset(&h, '\0', sizeof(h));
  /* the first char of hostname must be alphanmeric */
  if (NULL == strchr(Alphanum, *hostname))
  {
	  rfc1035SetErrno(3);
  	return 0;
  }
  if (qid > 0)
  {
    h.id = qid;
  }  
  else
  {
    h.id = rfc1035Qid();
  }  
    
  h.qr = 0;
  h.rd = 1;
  h.opcode = 0;		/* QUERY */
  h.qdcount = (unsigned int) 1;
  offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
  offset += rfc1035QuestionPack(buf + offset,
	                              sz - offset,
	                              hostname,
	                              RFC1035_TYPE_A,
	                              RFC1035_CLASS_IN);
  assert((unsigned)offset <= sz);
  *szp = (size_t) offset;
  return h.id;
}

/*
 * rfc1035BuildPTRQuery(const struct in_addr addr, char *buf, size_t * szp)
 *
 * Builds a message buffer with a QUESTION to lookup PTR records
 * for an address.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer, on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */
 unsigned short
DNSMessage::rfc1035BuildPTRQuery(const struct in_addr addr, char *buf, size_t * szp)
{
  return rfc1035BuildPTRQuery(addr, buf, szp, 0);
}  
/*
 * rfc1035BuildPTRQuery(const struct in_addr addr, char *buf, size_t * szp, short qid)
 *
 * Builds a message buffer with a QUESTION to lookup PTR records
 * for an address.  Caller must allocate 'buf' which should
 * probably be at least 512 octets.  The 'szp' initially
 * specifies the size of the buffer. The 'qid' specifies the query id for this
 * new query, for example, when this new query corresponds to a query
 * translation (from IP6.INT type to IN-ADDR.ARPA type), on return it contains
 * the size of the message (i.e. how much to write).
 * Return value is the query ID.
 */

unsigned short
DNSMessage::rfc1035BuildPTRQuery(const struct in_addr addr, char *buf, size_t * szp, unsigned short qid)
{
  static rfc1035_header h;
  off_t offset = 0;
  size_t sz = *szp;
  static char rev[32];
  unsigned int i;
  memset(&h, '\0', sizeof(h));
  i = (unsigned int) ntohl(addr.s_addr);
 /* snprintf(rev, 32, "%u.%u.%u.%u.in-addr.arpa.",
	        i & 255,
        	(i >> 8) & 255,
        	(i >> 16) & 255,
        	(i >> 24) & 255);*/
sprintf(rev, "%u.%u.%u.%u.in-addr.arpa.",
                i & 255,
                (i >> 8) & 255,
                (i >> 16) & 255,
                (i >> 24) & 255);
  if (qid > 0)
    h.id = qid;
  else
    h.id = rfc1035Qid();
    
  h.qr = 0;
  h.rd = 1;
  h.opcode = 0;		/* QUERY */
  h.qdcount = (unsigned int) 1;
  offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
  offset += rfc1035QuestionPack(buf + offset,
	                              sz - offset,
                              	rev,
                              	RFC1035_TYPE_PTR,
                              	RFC1035_CLASS_IN);
  assert((unsigned)offset <= sz);
  *szp = (size_t) offset;
  return h.id;
}
/*
 * rfc1035BuildPTR6Query(char * ipv6_addr, char *buf, size_t * szp)
 *
 * Does the same as rfc1035BuildPTRQuery, but for IPv6 addresses.
 * Builds a message buffer with a QUESTION to lookup PTR records
 * (in the ip6.int domain) for an IPv6 address.
 * ipv6_addr MUST be an array containing the IPv6 in it's EXPANDED
 * format (ie. 3ffe:1ce1:2:0:0:0:0:1). Caller must allocate 'buf' which
 * should probably be at least 512 octets.  The 'szp' initially specifies
 * the size of the buffer, on return it contains the size of the message
 * (i.e. how much to write). Return value is the query ID.
 */
unsigned short
DNSMessage::rfc1035BuildPTR6Query(char * ipv6_addr, char *buf, size_t * szp)
{
  return rfc1035BuildPTR6Query(ipv6_addr, buf, szp, 0);
}
/*
 * rfc1035BuildPTR6Query(char * ipv6_addr, char *buf, size_t * szp, short qid)
 *
 * Does the same as rfc1035BuildPTRQuery, but for IPv6 addresses.
 * Builds a message buffer with a QUESTION to lookup PTR records
 * (in the ip6.int domain) for an IPv6 address.
 * ipv6_addr MUST be an array containing the IPv6 in it's EXPANDED
 * format (ie. 3ffe:1ce1:2:0:0:0:0:1). Caller must allocate 'buf' which
 * should probably be at least 512 octets.  The 'szp' initially specifies
 * the size of the buffer. The 'qid' specifies the query id for this
 * new query, for example, when this new query corresponds to a query
 * translation (from IN-ADDR.ARPA type to IP6.INT type), on return it
 * contains the size of the message (i.e. how much to write). Return value
 * is the query ID.
 */
unsigned short
DNSMessage::rfc1035BuildPTR6Query(char * ipv6_addr, char *buf, size_t * szp, unsigned short qid)
{
  static rfc1035_header h;
  off_t offset = 0;
  size_t sz = *szp;
  char *new_ptr6_domain = rfc1035BuildPTR6Domain(ipv6_addr);
    
  memset(&h, '\0', sizeof(h));
  if (qid > 0)
    h.id = qid;
  else  
    h.id = rfc1035Qid();
    
  h.qr = 0;
  h.rd = 1;
  h.opcode = 0;		/* QUERY */
  h.qdcount = (unsigned int) 1;
  offset += rfc1035HeaderPack(buf + offset, sz - offset, &h);
  offset += rfc1035QuestionPack(buf + offset,sz - offset,new_ptr6_domain,RFC1035_TYPE_PTR,RFC1035_CLASS_IN);
    assert((unsigned)offset <= sz);
    *szp = (size_t) offset;
    return h.id;
}


/*
 * We're going to retry a former query, but we
 * just need a new ID for it.  Lucky for us ID
 * is the first field in the message buffer.
 */
unsigned short
DNSMessage::rfc1035RetryQuery(char *buf)
{
    unsigned short qid = rfc1035Qid();
    unsigned short s = htons(qid);
    memcpy(buf, &s, sizeof(s));
    return qid;
}

char *
DNSMessage::rfc1035BuildPTR6Domain(char *ipv6_addr)
{
  char *rev = new char[82];
	char *next_number = NULL;
 	int j,dif,k;
	memcpy(rev + 65,"ip6.int\0",9);

  j = 64;
  next_number = strtok(ipv6_addr,":");
  while (next_number !=NULL)
  {
    int number_len = strlen(next_number);
    if (number_len == 4)
    {
      rev[j] = '.';      
      rev[j - 1] = next_number[0];
      rev[j - 2] = '.';
      rev[j - 3] = next_number[1];
      rev[j - 4] = '.';
      rev[j - 5] = next_number[2];
      rev[j - 6] = '.';
      rev[j - 7] = next_number[3];
      j = j - 8;
    }
    else
    {
      dif = 4 - number_len;
      for (k = 0; k < dif; k++)
      {
      	// char *temp= new char[9];
        rev[j] = '.';
        j--;       
        rev[j] = '0';
        j--;        
      }
      for (k = 0; k < number_len; k++)
      {
        rev[j] = '.';
        j--;        
        rev[j] = next_number[k];
        j--;
      }
    }
    next_number = strtok(NULL,":");
  }
  int newlen = 82 - j;
  char *ptr = new char[newlen+1];
  memcpy(ptr,rev + j+1,newlen);
  return ptr;
  
}

char * 
DNSMessage:: my_strdup(const char *str)
{

  #ifdef CLICK_LINUXMODULE
	int n = strlen(str)+1;
        char *s = (char *)kmalloc(n, GFP_KERNEL);
	if (!s) 
          return NULL;
	return strcpy(s, str);
  #else
   return strdup(str);
  #endif
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(DNSMessage)
