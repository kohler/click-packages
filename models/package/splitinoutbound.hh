#ifndef SPLITINOUTBOUND_HH
#define SPLITINOUTBOUND_HH
#include <click/element.hh>
#include <click/bighashmap.hh>
#include <cstdio.h>

/* split a trace stream into two directions (normally, inbound and outbound traffic)
 * SplitInOutBound("filename")
 * <filename> contains a list of inbound address names
 */

class SplitInOutBound : public Element { public:

    SplitInOutBound();
    ~SplitInOutBound();

    const char *class_name() const { return "SplitInOutBound";}
    SplitInOutBound *clone() const { return new SplitInOutBound; }

    const char *processing() const { return "a/ahhhh";}
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);

    void push(int,Packet *);

    IPAddress getNetworkAddr(IPAddress, int &);
    Packet * handle_packet(Packet *);

    private:

    String _infilename;
    String _outfilename;


    typedef BigHashMap<IPAddress,int> address_table;
    address_table _hash_inoutaddresses;
};
    
#endif
