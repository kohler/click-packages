#ifndef CLICK_DNS_HH
#define CLICK_DNS_HH

#include <click/config.h>
#include <click/confparse.hh>
#include <clicknet/rfc1035.h>
#include <click/router.hh>
#include <click/elemfilter.hh>
#include <click/error.hh>
#include <linux/slab.h>
#ifndef CLICK_LINUXMODULE
  #include <string.h>
#endif

CLICK_DECLS
class DNSMessage {
  public:

  	DNSMessage();
    unsigned short rfc1035BuildAQuery(const char *hostname,char *buf,size_t * szp);
    unsigned short rfc1035BuildAQuery(const char *hostname,char *buf,size_t * szp, unsigned short qid);    
    unsigned short rfc1035BuildAAAAQuery(const char *hostname, char *buf, size_t * szp);
    unsigned short rfc1035BuildAAAAQuery(const char *hostname, char *buf, size_t * szp, unsigned short qid);
    unsigned short rfc1035BuildPTRQuery(const struct in_addr,char *buf,size_t * szp);
    unsigned short rfc1035BuildPTRQuery(const struct in_addr addr, char *buf, size_t * szp, unsigned short qid);    
    unsigned short rfc1035BuildPTR6Query(char * ipv6_addr, char *buf, size_t * szp);
    unsigned short rfc1035BuildPTR6Query(char * ipv6_addr, char *buf, size_t * szp, unsigned short qid);
    unsigned short rfc1035RetryQuery(char *);
    int rfc1035HeaderUnpack(const char *buf, size_t sz, off_t * off, rfc1035_header * h);
    int rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, size_t ns);
    int rfc1035RRUnpack(const char *buf, size_t sz, off_t * off, rfc1035_rr * RR);
    int rfc1035AnswersUnpack(const char *buf,size_t sz,rfc1035_rr ** records ,rfc1035_rr ** authorities,
                             rfc1035_rr ** additionals,unsigned short *id,off_t *off);
    off_t rfc1035HeaderPack(char *buf, size_t sz, rfc1035_header * hdr);
    off_t rfc1035QuestionPack(char *buf,size_t sz,const char *name,unsigned short type,unsigned short _class);
    int rfc1035RRPack(rfc1035_rr *RR, off_t * off, char *buf, size_t sz);    
    void rfc1035RRDestroy(rfc1035_rr * rr, int n);
    unsigned short rfc1035BuildFailedQueryResponse(const char *query, int qtype, char *buf, size_t * szp, unsigned short qid);

    char * rfc1035BuildPTR6Domain(char *ipv6_addr);    
    const char *rfc1035_error_message;
    char *my_strdup(const char *str);

  private:    
    off_t rfc1035LabelPack(char *buf, size_t sz, const char *label);
    off_t rfc1035NamePack(char *buf, size_t sz, const char *name);
    unsigned short rfc1035Qid(void);
    void rfc1035SetErrno(int n);
    int rfc1035_errno;

};
CLICK_ENDDECLS
#endif
