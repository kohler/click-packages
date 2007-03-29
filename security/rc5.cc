#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "rc5.hh"

// This file is copyright 2005/2006 by the International Computer
// Science Institute.  It can be used for any purposes
// (Berkeley-liscence) as long as this notice remains intact.

// THERE IS NO WARANTEE ON THIS CODE!



// Implementation for RC5, 32 bit, 3 rounds, 32 bit key (RC5/32/3/32)
// which is what's used as the random permutation for the address
// table, and for the pRNG for the random dropper.  This is a WEAK
// cypher, but as the attacker doesn't really have insight into the
// table state, AND since blowing out the table really doesn't buy
// much unless the attacker has tons of IPs, this isn't a problem.

// Modified from applied crypto, and my simple sim

#define RC5_ROUNDS 3

#define ROTR16(x,c) ((uint16_t) (((x)>>((c) & 0xf))|((x)<<(16-((c) & 0xf)))))
#define ROTL16(x,c) ((uint16_t) (((x)<<((c) & 0xf))|((x)>>(16-((c) & 0xf)))))
CLICK_DECLS
uint16_t *rc5_keygen(uint64_t key){
    uint16_t *keyArray;
    uint16_t lArray[4];
    int i = 0;
    int j = 0;
    int k = 0;
    uint16_t A = 0;
    uint16_t B = 0;
    lArray[0] = key;
    lArray[1] = key >> 16;
    lArray[2] = key >> 32;
    lArray[3] = key >> 48;
    keyArray = new uint16_t[2 * (RC5_ROUNDS + 1)];
    keyArray[0] = 0xb7e5;
    for(i = 1; i < (2 * (RC5_ROUNDS + 1)); ++i){
	keyArray[i] = (keyArray[i-1] + 0x9e37);
    }
    i = 0; j = 0;
    for(k = 0; k < 6 * (RC5_ROUNDS + 1); ++k){
	A = ROTL16( keyArray[i] + A + B, 3);
	keyArray[i] = A;
	B = ROTL16( lArray[j] + A + B, A + B);
	lArray[j] = B;
	i++;
	j++;
	i = i % (2 * (RC5_ROUNDS + 1));
	j = j % 4;
    }
    /*   click_chatter("Key array for initial key %i is\n", key);
	 for(i = 0; i < (2 * (numRounds + 1)); ++i){
	 click_chatter("%2i   0x%4x\n",i,keyArray[i]);
    } */
    return keyArray;
}

uint32_t rc5_encrypt(uint32_t data, uint16_t *key){
    uint16_t a, b;
    uint32_t result;
    int i;
    a = (data & 0xffff);
    b = ((data >> 16) & 0xffff);
    a += key[0];
    b += key[1];
    for(i = 1; i <= RC5_ROUNDS; ++i){
	a = a ^ b;
	a = ROTL16(a,b);
	a = a + key[2 * i];
	b = ROTL16((b ^ a), a);
	b = b + key[2 * i + 1];
    }
    result = b;
    result = result << 16;
    result = result | a;
    return result;
}

uint32_t rc5_decrypt(uint32_t data, uint16_t *key){
    uint16_t a, b;
    uint32_t result;
    int i;
    a = (data & 0xffff);
    b = ((data >> 16) & 0xffff);
    for(i = RC5_ROUNDS; i >= 1; --i){
	b = b - key [2 * i + 1];
	b = ROTR16(b,a);
	b = b ^ a;

	a = a - key [2 * i];
	a = ROTR16(a,b);
	a = a ^ b;
    }
    b = b - key[1];
    a = a - key[0];

    result = b;
    result = result << 16;
    result = result | a;
    return result;
}
CLICK_ENDDECLS
ELEMENT_PROVIDES(rc5)

