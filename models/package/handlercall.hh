// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_HANDLERCALL_HH
#define CLICK_HANDLERCALL_HH
#include <click/string.hh>
class Element;
class ErrorHandler;

class HandlerCall { public:

    HandlerCall()		: _e(0), _hi(-1) { }
    HandlerCall(const String &s): _e(0), _hi(-1), _value(s) { }

    bool ok() const		{ return _hi >= 0; }
    bool is_read() const;

    int initialize(bool write, Element *, ErrorHandler *);
    int initialize(String, bool write, Element *, ErrorHandler *);
    int initialize_read(Element *, ErrorHandler *);
    int initialize_read(const String &, Element *, ErrorHandler *);
    int initialize_write(Element *, ErrorHandler *);
    int initialize_write(const String &, Element *, ErrorHandler *);

    String call_read(Element *context);
    int call_write(Element *context, ErrorHandler * = 0);
    
  private:
    
    static const char * const READ_MARKER = "r";
    
    Element *_e;
    int _hi;
    String _value;

};

inline bool
HandlerCall::is_read() const
{
    return _value.data() == READ_MARKER;
}

inline int
HandlerCall::initialize(bool write, Element *context, ErrorHandler *errh)
{
    return initialize(_value, write, context, errh);
}

inline int
HandlerCall::initialize_read(const String &s, Element *context, ErrorHandler *errh)
{
    return initialize(s, false, context, errh);
}

inline int
HandlerCall::initialize_read(Element *context, ErrorHandler *errh)
{
    return initialize(_value, false, context, errh);
}

inline int
HandlerCall::initialize_write(const String &s, Element *context, ErrorHandler *errh)
{
    return initialize(s, true, context, errh);
}

inline int
HandlerCall::initialize_write(Element *context, ErrorHandler *errh)
{
    return initialize(_value, true, context, errh);
}

#endif
