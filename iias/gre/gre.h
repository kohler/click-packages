/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef GRE_H
#define GRE_H
#include <click/cxxprotect.h>
CLICK_CXX_PROTECT

/*
 * our own definitions of GRE headers
 * based on a file from one of the BSDs
 */

#define GRE_CP          0x8000  /* Checksum Present */
#define GRE_RP          0x4000  /* Routing Present */
#define GRE_KP          0x2000  /* Key Present */
#define GRE_SP          0x1000  /* Sequence Present */
#define GRE_SS		0x0800	/* Strict Source Route */
#define GRE_VERSION     0x0007  /* Version Number */

struct click_gre {
    uint16_t flags;		/* See above */
    uint16_t protocol;		/* Ethernet protocol type */
    uint16_t checksum;		/* present if (flags & GRE_CP) */
    uint16_t reserved1;		/* present if (flags & GRE_CP) */
    uint32_t key;		/* present if (flags & GRE_KP) */
    uint32_t seq;		/* present if (flags & GRE_SP) */
};

CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>
#endif
