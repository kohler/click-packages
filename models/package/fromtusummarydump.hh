// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_FROMTUSUMMARYDUMP_HH
#define CLICK_FROMTUSUMMARYDUMP_HH
#include <click/element.hh>
#include <click/task.hh>

class FromTUSummaryDump : public Element { public:

    FromTUSummaryDump();
    ~FromTUSummaryDump();

    const char *class_name() const	{ return "FromTUSummaryDump"; }
    FromTUSummaryDump *clone() const	{ return new FromTUSummaryDump; }
    const char *processing() const	{ return AGNOSTIC; }

    int configure(const Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void uninitialize();
    void add_handlers();

    Packet *pull(int);
    void run_scheduled();
    
  private:

    int _fd;

    char *_buf;
    int _pos;
    int _len;
    int _cap;
    
    String _filename;
    Task _task;
    bool _active;
    bool _stop;

    bool read_more_buf();
    Packet *try_read_packet();
    Packet *read_packet();
    
};

#endif
