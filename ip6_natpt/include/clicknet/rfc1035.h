/*
* Implementation of RFC 1035 (DNS).
* Code taken from Squid Proxy Server http://www.squid-cache.org
* By: Duane Wessels <wessels@squid-cache.org>
*
* Added DNS IPv6 extensions by: Juan Luis Baptiste <juancho@linuxmail.org>
*
* Distributed under de GNU General Public License (GNU/GPL).
*
*/
#ifndef _RFC1035_H_
#define _RFC1035_H_

//#include <memory.h>
#include <assert.h>


/* rfc1035 - DNS */
#define RFC1035_TYPE_A 1
#define RFC1035_TYPE_AAAA 28
#define RFC1035_TYPE_PTR 12
#define RFC1035_TYPE_NS 2
#define RFC1035_CLASS_IN 1
#define RFC1035_MAXHOSTNAMESZ 128
#define RFC1035_MAXLABELSZ 63
#define rfc1035_unpack_error 15

static const char *Alphanum =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789";

typedef struct _rfc1035_header rfc1035_header;

//int rfc1035_errno;
//const char *rfc1035_error_message;
struct _rfc1035_header {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

typedef struct _rfc1035_rr rfc1035_rr;
struct _rfc1035_rr {
  char name[RFC1035_MAXHOSTNAMESZ];
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short rdlength;
  char *rdata;
};
#endif /* ndef _RFC1035_H_ */
