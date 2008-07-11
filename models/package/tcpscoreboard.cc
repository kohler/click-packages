// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>
#include "tcpscoreboard.hh"
CLICK_DECLS

void
TCPScoreboard::add(tcp_seq_t seq, tcp_seq_t end_seq)
{
    // common cases
    if (SEQ_GEQ(seq, end_seq) || SEQ_LEQ(end_seq, _cumack))
	/* nothing to do */;
    else if (SEQ_LEQ(seq, _cumack) && !_sack.size())
	_cumack = end_seq;
    else if (SEQ_LEQ(seq, _cumack)) {
	_cumack = end_seq;
	while (_sack.size() && SEQ_GEQ(_cumack, _sack[0])) {
	    if (SEQ_LT(_cumack, _sack[1]))
		_cumack = _sack[1];
	    _sack.pop_front();
	    _sack.pop_front();
	}
    } else if (!_sack.size() || SEQ_GT(seq, _sack.back())) {
	_sack.push_back(seq);
	_sack.push_back(end_seq);
    } else {
	int block;
	for (block = 0; block < _sack.size(); block += 2)
	    if (SEQ_LEQ(seq, _sack[block + 1])) {
		if (SEQ_LT(end_seq, _sack[block])) { // add new block
		    _sack.push_back(0);
		    _sack.push_back(0);
		    for (int i = _sack.size() - 1; i >= block + 2; i--)
			_sack[i] = _sack[i - 2];
		    _sack[block] = seq;
		    _sack[block+1] = end_seq;
		} else {
		    if (SEQ_LEQ(seq, _sack[block]))
			_sack[block] = seq;
		    if (SEQ_GEQ(end_seq, _sack[block+1]))
			_sack[block+1] = end_seq;
		}
		break;
	    }
    }
}

bool
TCPScoreboard::contains(tcp_seq_t seq, tcp_seq_t end_seq) const
{
    // common cases
    if (seq == end_seq)
	return false;
    else if (SEQ_LEQ(end_seq, _cumack))
	return true;
    else {
	if (SEQ_LT(seq, _cumack))
	    seq = _cumack;
	for (int block = 0; block < _sack.size(); block += 2)
	    if (SEQ_LT(seq, _sack[block]))
		return false;
	    else if (SEQ_LEQ(end_seq, _sack[block+1]))
		return true;
	    else if (SEQ_LEQ(seq, _sack[block+1]))
		seq = _sack[block+1];
	return false;
    }
}

ELEMENT_PROVIDES(TCPScoreboard)
CLICK_ENDDECLS
