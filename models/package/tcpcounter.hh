#ifndef TCPCOUNTER_HH
#define TCPCOUNTER_HH

#include <click/element.hh>
#include <click/glue.hh>
#include <click/bighashmap.hh>

class TCPCounter : public Element {

    public:
    TCPCounter();
    ~TCPCounter();

    const char *class_name() const { return "TCPCounter";}
    TCPCounter *clone() const {return new TCPCounter;}
    const char *processing() const { return AGNOSTIC;}

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void add_handlers();

    
    class TCPConnection{
	public:
	TCPConnection(IPAddress s, uint32_t sport, IPAddress d, uint32_t dport ) { 
	    srcip = s; 
	    srcport = sport; 
	    dstip = d; 
	    dstport = dport;
	}

	IPAddress srcip;
	IPAddress dstip;
	uint32_t srcport;
	uint32_t dstport;

	bool operator==(const TCPConnection &b) {
	    return ((srcip == b.srcip)  && 
		    (srcport  == b.srcport) && 
		    (dstip == b.dstip) && 
		    (dstport == b.dstport));
	}
    };

    class TCPConnectionCounter{
	public:
	TCPConnectionCounter(struct timeval stime, unsigned int s):total_pkts_lost(0),reordered(false){
	    start_time = stime;
	    start_seqno = s;
	    seq_no = s;
	    end_time.tv_sec = 0;
	    end_time.tv_usec = 0;
	}

	unsigned int total_bytes;
	struct timeval start_time;
	struct timeval end_time;
	unsigned int total_pkts_lost;

	unsigned int seq_no;
	unsigned int start_seqno;

	bool reordered;
    };

    typedef BigHashMap<TCPConnection, TCPConnectionCounter> tcpcounter_table;
    tcpcounter_table _hashed_tcpcounters;

    Packet *simple_action(Packet *);
    void print_connection(TCPConnection &, TCPConnectionCounter *);

};

#endif
