// -*- c-basic-offset: 4 -*-
#ifndef CLICK_TCPSCOREBOARD_HH
#define CLICK_TCPSCOREBOARD_HH
#include <clicknet/tcp.h>
#include <click/dequeue.hh>
CLICK_DECLS

class TCPScoreboard { public:

    TCPScoreboard(tcp_seq_t cumack = 0)	: _cumack(cumack) { }

    void clear(tcp_seq_t cumack = 0)	{ _cumack = cumack; }
    void add(tcp_seq_t seq, tcp_seq_t end_seq);
    bool contains(tcp_seq_t seq, tcp_seq_t end_seq) const;
    inline tcp_seq_t cumack() const	{ return _cumack; }

  public:

    tcp_seq_t _cumack;
    DEQueue<tcp_seq_t> _sack;

};

CLICK_ENDDECLS
#endif
