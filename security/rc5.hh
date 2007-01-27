#ifndef NW_RC5_HH
#define NW_RC5_HH
#include <click/element.hh>

// This file is copyright 2005/2006 by the International Computer
// Science Institute.  It can be used for any purposes
// (Berkeley-liscence) as long as this notice remains intact.

// THERE IS NO WARANTEE ON THIS CODE!

uint16_t * rc5_keygen(uint64_t key);
uint32_t rc5_encrypt(uint32_t data, uint16_t *key);
uint32_t rc5_decrypt(uint32_t data, uint16_t *key);

#endif
