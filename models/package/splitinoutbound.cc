#include <config.h>
#include <click/config.h>

#include "splitinoutbound.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/confparse.hh>
#include <packet_anno.hh>

SplitInOutBound::SplitInOutBound() : Element(1,1) 
{
    MOD_INC_USE_COUNT;
}

SplitInOutBound::~SplitInOutBound()
{
    MOD_DEC_USE_COUNT;
}

int
SplitInOutBound::configure(const Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_parse(conf, this, errh, 
		    cpFilename, "filename for inbound addresses", &_infilename,
		    cpFilename, "filename for output inbound addresses", &_outfilename,
		    0) < 0)
	return -1;

    return 0;
}

int
SplitInOutBound::initialize(ErrorHandler *errh)
{
    FILE *f;

    if ((f = fopen(_infilename.cc(), "r")) == NULL) 
	return errh->error("%s: %s", _infilename.cc(), strerror(errno));

    //read all the addresses in the file to hashmap
    IPAddress ipaddr;
    int addr[4];

    while (1) {
	if (fscanf(f,"%u.%u.%u.%u\n",&addr[0],&addr[1],&addr[2],&addr[3]) != 4) {
	    if (feof(f)) break;
	}
	ipaddr = IPAddress(htonl((addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3]));

	//insert it into bighashmap
	int *inout = _hash_inoutaddresses.findp(ipaddr);
	if (!inout) {
	    int isin = 1;
	    _hash_inoutaddresses.insert(ipaddr,isin);
	}else{
	    click_chatter("dupliate!\n");
	}
    }
    return 0;
}

void
SplitInOutBound::push(int, Packet *p)
{
    if (Packet *q = handle_packet(p))
	output(2).push(q); //error packets got thrown out
}


IPAddress
SplitInOutBound::getNetworkAddr(IPAddress addr)
{
    //check for class A/B/C
    int address = ntohl(addr.addr());
    //i cannot stand network/host order!!!
   
    int prefix = address & 0xF0000000;

    if (prefix < 8 ) { //the first bit of class A address is 0
	address = address & 0xFF000000;
	return IPAddress(htonl(address));
    }else if (prefix < 12 ) { //the first two bit of class B address are 10
	address = address & 0xFFFF0000;
	return IPAddress(htonl(address));
    }else if (prefix < 14) { //the first three bits of class C address are 110
	address = address & 0xFFFFFF00;
	return IPAddress(htonl(address));
    }else {
	return addr;
    }

}

Packet *
SplitInOutBound::handle_packet(Packet *p)
{
    //port 1 is inbound  traffic, i.e. packets with inbound dst ip address
    const click_ip *iph = p->ip_header();
    IPAddress dstaddr = getNetworkAddr(IPAddress(iph->ip_src));
    IPAddress srcaddr = getNetworkAddr(IPAddress(iph->ip_dst));

    int *in = _hash_inoutaddresses.findp(dstaddr);
    if (in) {
	if (*in == 1) {
	    //the src addr must be an outbound address then
	    *in = 0;
	    _hash_inoutaddresses.insert(srcaddr,*in);
	    //this is an inbound packet
	    output(1).push(p);
	}else {
	    *in = 1;
	    _hash_inoutaddresses.insert(srcaddr,*in);
	    output(0).push(p);
	}
	return NULL;
    }

    in = _hash_inoutaddresses.findp(srcaddr);

    if (in) {
	if (*in == 0) {
	    //this is an inbound packet
	    *in = 1;
	    _hash_inoutaddresses.insert(dstaddr,*in);
	    output(1).push(p);
	}else {
	    *in = 0;
	    _hash_inoutaddresses.insert(dstaddr,*in);
	    output(0).push(p);
	}
	return NULL;
    }

    //else i do not know what to do with it, 
    return p;
}

EXPORT_ELEMENT(SplitInOutBound);
#include <click/bighashmap.cc>

