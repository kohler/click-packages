// -*- c-basic-offset: 4 -*-
#include <config.h>
#include <click/config.h>

#include "aggregatenotifier.hh"

void
AggregateListener::aggregate_notify(uint32_t, AggregateEvent, const Packet *)
{
}

void
AggregateNotifier::add_listener(AggregateListener *l)
{
    for (int i = 0; i < _listeners.size(); i++)
	if (_listeners[i] == l)
	    return;
    _listeners.push_back(l);
}

void
AggregateNotifier::remove_listener(AggregateListener *l)
{
    for (int i = 0; i < _listeners.size(); i++)
	if (_listeners[i] == l) {
	    _listeners[i] = _listeners.back();
	    _listeners.pop_back();
	    return;
	}
}

ELEMENT_REQUIRES(userlevel)
ELEMENT_PROVIDES(AggregateNotifier)