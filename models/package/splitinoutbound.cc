#include <config.h>
#include <click/config.h>

#include "splitinoutbound.hh"
#include <click/error.hh>
#include <click/hashmap.hh>
#include <click/confparse.hh>
#include <packet_anno.hh>

SplitInOutBound::SplitInOutBound() : Element(1,5) 
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
    int isin;

    while (1) {
	if (fscanf(f,"%u.%u.%u.%u %u\n",&addr[0],&addr[1],&addr[2],&addr[3],&isin) != 5) {
	    if (feof(f)) break;
	}
	ipaddr = IPAddress(htonl((addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3]));

	printf("insert %s (%d)\n",ipaddr.unparse().cc(),isin);
	//insert it into bighashmap
	int *inout = _hash_inoutaddresses.findp(ipaddr);
	if (!inout) {
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
	output(4).push(q); //error packets got thrown out
}


IPAddress
SplitInOutBound::getNetworkAddr(IPAddress addr, int & is_multicast)
{
    //check for class A/B/C
    int address = ntohl(addr.addr());
    //i cannot stand network/host order!!!
  
    assert(is_multicast == 0);

    int prefix = (address & 0xF0000000) >> 28;

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
	is_multicast = 1;
	return addr;
    }

}

Packet *
SplitInOutBound::handle_packet(Packet *p)
{
    //port 1 is inbound  traffic, i.e. packets with inbound dst ip address
    const click_ip *iph = p->ip_header();

    int *in;
    int in_compl;

    int dstmulticast = 0;
    IPAddress dstaddr = getNetworkAddr(IPAddress(iph->ip_dst), dstmulticast);

    int srcmulticast = 0;
    IPAddress srcaddr = getNetworkAddr(IPAddress(iph->ip_src), srcmulticast);
    assert(srcmulticast == 0);

    if (dstmulticast) {
	in = _hash_inoutaddresses.findp(srcaddr);
	if (in && (*in == 1)) {
	    //src address is an inbound addr
	    output(3).push(p);
	}else{
	    output(2).push(p);
	}

	return NULL;
    }

    in = (int *)_hash_inoutaddresses.findp(dstaddr);


    if (in) {
	in_compl = (*in+1) % 2;
	if (*in == 1) {
	    //dst inbound and the src addr must be an outbound address then
	    if (!_hash_inoutaddresses.findp(srcaddr)) _hash_inoutaddresses.insert(srcaddr,in_compl);

	    //this is an inbound packet
	    output(1).push(p);
	}else {
	    if (!_hash_inoutaddresses.findp(srcaddr)) _hash_inoutaddresses.insert(srcaddr,in_compl);
	    output(0).push(p);
	}
	return NULL;
    }

    in = (int *)_hash_inoutaddresses.findp(srcaddr);

    if (in) {
	in_compl = (*in+1) % 2;
	if (*in == 0) {
	    //src is out-addr, so dst must be in-addr, this is an inbound packet
	    //the entry associated with dstaddr must be NULL
	    _hash_inoutaddresses.insert(dstaddr,in_compl);
	    output(1).push(p);
	}else {
	    _hash_inoutaddresses.insert(dstaddr,in_compl);
	    output(0).push(p);
	}
	return NULL;
    }

    //else i do not know what to do with it, 
    return p;
}

EXPORT_ELEMENT(SplitInOutBound);
#include <click/bighashmap.cc>

