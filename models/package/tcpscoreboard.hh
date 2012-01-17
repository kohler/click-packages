// -*- c-basic-offset: 4 -*-
#ifndef CLICK_TCPSCOREBOARD_HH
#define CLICK_TCPSCOREBOARD_HH
#include <clicknet/tcp.h>
#include <click/deque.hh>
CLICK_DECLS

class TCPScoreboard { public:

    TCPScoreboard(tcp_seq_t cumack = 0)	: _cumack(cumack) { }

    inline tcp_seq_t cumack() const	{ return _cumack; }
    bool contains(tcp_seq_t seq, tcp_seq_t end_seq) const;

    inline void clear(tcp_seq_t cumack = 0);
    void add(tcp_seq_t seq, tcp_seq_t end_seq);
    inline void add_cumack(tcp_seq_t cumack);

  public:

    tcp_seq_t _cumack;
    Deque<tcp_seq_t> _sack;

};

inline void TCPScoreboard::clear(tcp_seq_t cumack)
{
    _cumack = cumack;
    _sack.clear();
}

inline void TCPScoreboard::add_cumack(tcp_seq_t cumack)
{
    add(_cumack, cumack);
}

CLICK_ENDDECLS
#endif
