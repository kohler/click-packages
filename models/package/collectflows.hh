// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_COLLECTTCPFLOWS_HH
#define CLICK_COLLECTTCPFLOWS_HH
#include <click/element.hh>
#include <click/ipflowid.hh>
#include <click/bighashmap.hh>

/*
=c

CollectTCPFlows([FILENAME, I<KEYWORDS>])

=s

collects information about TCP flows


*/

class CollectTCPFlows : public Element { public:

    class Flow;

    CollectTCPFlows();
    ~CollectTCPFlows();

    const char *class_name() const	{ return "CollectTCPFlows"; }
    CollectTCPFlows *clone() const	{ return new CollectTCPFlows; }

    void notify_noutputs(int);
    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void uninitialize();
    void add_handlers();

    Packet *handle_packet(Packet *);
    void push(int, Packet *);
    Packet *pull(int);

    void write_session(const Flow *);
    
  private:

    typedef BigHashMap<IPFlowID, Flow *> Map;
    Map _map;
    Flow *_last_flow;

    Flow *_done_head;
    Flow *_done_tail;
    struct timeval _done_timestamp;

    FILE *_f;
    String _filename;
    bool _gen_packets;
    
    Packet *bad_packet(Packet *);
    Flow *add_flow(const IPFlowID &, Packet *);
    void pass_over_done(const struct timeval &);

    void clear(bool write);
    void write_flow(const Flow *);

    static int flush_handler(const String &, Element*, void*, ErrorHandler*);
    
};


class CollectTCPFlows::Flow { public:

    static bool make_pair(const IPFlowID &, Flow **, Flow **);

    const IPFlowID &flow_id() const	{ return _flow; }
    
    const Flow *primary() const	{ return _is_primary ? this : _reverse; }
    Flow *primary()		{ return _is_primary ? this : _reverse; }
    bool is_primary() const	{ return _is_primary; }
    Flow *reverse() const	{ return _reverse; }

    int protocol() const	{ return 6; }
    
    const struct timeval &first_session_timestamp() const;
    const struct timeval &last_session_timestamp() const;

    uint32_t packet_count() const	{ return _packet_count; }
    
    void clear(bool is_primary);
    
    bool session_over() const	{ return _flow_over && _reverse->_flow_over; }
    void set_flow_over()	{ _flow_over = true; }
    void set_session_over()	{ _flow_over = _reverse->_flow_over = true; }

    bool free_tracked() const	{ return _free_tracked; }
    Flow *free_next() const	{ return _free_next; }
    inline void add_to_free_tracked_tail(Flow *&head, Flow *&tail);
    inline void append_to_free(Flow *&head, Flow *&tail);
    inline Flow *free_from_free(Map &);
    void clear_free_tracked()	{ _free_tracked = _reverse->_free_tracked = false; _free_next = 0; assert(_reverse->_free_next == 0); }

    inline bool used_since(const struct timeval &) const;
    
    inline void update(const Packet *, CollectTCPFlows *);
    
  private:
    
    IPFlowID _flow;
    Flow *_reverse;
    
    uint32_t _packet_count;
    uint64_t _byte_count;
    
    struct timeval _first_ts;
    struct timeval _last_ts;
    
    bool _is_primary : 1;
    bool _flow_over : 1;
    bool _free_tracked : 1;
    
    Flow *_free_next;

    Flow(const IPFlowID &, bool);

    friend class CollectTCPFlows;
    
};

inline
CollectTCPFlows::Flow::Flow(const IPFlowID &flowid, bool is_primary)
    : _flow(flowid), _packet_count(0), _byte_count(0),
      _is_primary(is_primary), _flow_over(false), _free_tracked(false),
      _free_next(0)
{
    timerclear(&_first_ts);
    timerclear(&_last_ts);
}

inline void
CollectTCPFlows::Flow::clear(bool is_primary)
{
    _packet_count = 0;
    _byte_count = 0;
    _is_primary = is_primary;
    _flow_over = false;
    timerclear(&_first_ts);
    timerclear(&_last_ts);
}

inline void
CollectTCPFlows::Flow::append_to_free(Flow *&head, Flow *&tail)
{
    assert((!head && !tail)
	   || (head && tail && head->_free_tracked && tail->_free_tracked));
    assert(!_free_next && !_reverse->_free_next);
    if (tail)
	tail = tail->_free_next = this;
    else
	head = tail = this;
}

inline void
CollectTCPFlows::Flow::add_to_free_tracked_tail(Flow *&head, Flow *&tail)
{
    assert(!_free_tracked && !_reverse->_free_tracked);
    _free_tracked = _reverse->_free_tracked = true;
    primary()->append_to_free(head, tail);
}

inline bool
CollectTCPFlows::Flow::used_since(const struct timeval &when) const
{
    return timercmp(&_last_ts, &when, >) || timercmp(&_reverse->_last_ts, &when, >);
}

inline const struct timeval &
CollectTCPFlows::Flow::first_session_timestamp() const
{
    // by definition, primary's first timestamp is first
    return primary()->_first_ts;
}

inline const struct timeval &
CollectTCPFlows::Flow::last_session_timestamp() const
{
    if (timercmp(&_last_ts, &_reverse->_last_ts, >))
	return _last_ts;
    else
	return _reverse->_last_ts;
}

#endif
