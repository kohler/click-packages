// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>

#include "handlercall.hh"
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/error.hh>

const char * const HandlerCall::READ_MARKER = "r";

int
HandlerCall::initialize(String what, bool write, Element *context, ErrorHandler *errh)
{
    _e = 0;
    _hi = -1;
    _value = String();

    if (write)
	return cp_va_space_parse
	    (what, context, errh,
	     cpWriteHandler, "write handler name", &_e, &_hi,
	     cpOptional,
	     cpString, "value", &_value,
	     0);
    else
	return cp_va_space_parse
	    (what, context, errh,
	     cpReadHandler, "read handler name", &_e, &_hi,
	     0);
}

String
HandlerCall::call_read(Element *context)
{
    if (!ok() || !is_read())
	return String();
    const Router::Handler &h = context->router()->handler(_hi);
    return h.call_read(_e);
}

int
HandlerCall::call_write(Element *context, ErrorHandler *errh)
{
    if (!errh)
	errh = ErrorHandler::default_handler();
    if (!ok() || is_read())
	return errh->error("not a write handler");
    const Router::Handler &h = context->router()->handler(_hi);
    return h.call_write(_value, _e, errh);
}

ELEMENT_PROVIDES(HandlerCall)
