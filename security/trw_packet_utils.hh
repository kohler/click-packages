#ifndef NW_PUTILS_HH
#define NW_PUTILS_HH
#include <click/element.hh>

// This file is copyright 2005/2006 by the International Computer
// Science Institute.  It can be used for any purposes
// (Berkeley-liscence) as long as this notice remains intact.

// THERE IS NO WARANTEE ON THIS CODE!


// On TRW, does this packet get blocked if a system is being blocked?
bool block_policy(Packet *p);

// Is this packet really an acknowledgement?
bool valid_ack(Packet *p);

#endif
