// -*- mode: c++; c-basic-offset: 4 -*-
#include <click/config.h>

#include "handlercall.hh"
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/error.hh>

int
HandlerCall::initialize(String what, bool write, Element *context, ErrorHandler *errh)
{
    _e = 0;
    _hi = -1;
    _value = String();

    if (write)
	return cp_va_space_parse(what, context, errh,
				 cpWriteHandler, "write handler name", &_e, &_hi,
				 cpOptional,
				 cpString, "value", &_value,
				 0);
    else
	return cp_va_space_parse(what, context, errh,
				 cpReadHandler, "read handler name", &_e, &_hi,
				 0);
}

String
HandlerCall::call_read(Element *context)
{
    if (!ok())
	return String();
    const Router::Handler &h = context->router()->handler(_hi);
    return h.call_read(_e);
}

int
HandlerCall::call_write(Element *context, ErrorHandler *errh)
{
    if (!ok())
	return String();
    if (!errh)
	errh = ErrorHandler::default_handler();
    const Router::Handler &h = context->router()->handler(_hi);
    return h.call_write(_value, _e, errh);
}

ELEMENT_PROVIDES(HandlerCall)
