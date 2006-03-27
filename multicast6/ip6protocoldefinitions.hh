#ifndef IP6PROTOCOLDEFINITIONS_HH
#define IP6PROTOCOLDEFINITIONS_HH
#include <clicknet/ip6.h>

/*******************************************************************************************
 *                                                                                         *
 * MLD protocol headers below                                                              *
 *                                                                                         *
 *******************************************************************************************/

struct mldv1message {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short responsecode;
  unsigned short reserved;
  click_in6_addr group;
};


struct mldv2querie {
  unsigned char type;            // 1 byte
  unsigned char code;            // 1 byte
  unsigned short checksum;       // 2 byte
  unsigned short responsecode;   // 2 byte
  unsigned short reserved;       // 2 byte
  click_in6_addr group;          // 16 byte
  unsigned char res_and_s_and_qrv;       // 1 byte
  unsigned char qqic;            // 1 byte
  unsigned short no_of_sources;  // 2 byte
  //	IP6Address sources[1];
};

struct grouprecord {
  unsigned char type;
  unsigned char aux_data_len;
  unsigned short no_of_sources;
  click_in6_addr multicast_address;
  click_in6_addr sources[1];
};

struct mldv2report {
  unsigned char type;
  unsigned char reserved;
  unsigned short checksum;
  unsigned short reserved_short;
  unsigned short no_of_grouprecords;
  struct grouprecord grouprecords[1];
};


/*******************************************************************************************
 *                                                                                         *
 * PIM protocol headers below                                                              *
 *                                                                                         *
 *******************************************************************************************/

// 1
struct Pim_Header {
  uint8_t ver_type;
  uint8_t reserved;
  uint16_t checksum;
};

struct Pim_Options {
  uint16_t type;
  uint16_t len;
  uint32_t value;
};

struct Pim_Holdtime {
  uint16_t type;
  uint16_t len;
  uint16_t value;
};


struct Pim_Register {
  uint16_t bn_reserved;
};

// 2
struct Pim_IPv6_Unicast {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t addr[16];
};

struct Pim_IPv6_Group {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t reserved;
  uint8_t mask_len;
  click_in6_addr addr;
};

// 5 = 20 byte
struct Pim_IPv6_Source {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t swr;
  uint8_t mask_len;
  click_in6_addr addr;
};

struct Pim_IPv6_Register_Stop {
  Pim_IPv6_Group group;
  Pim_IPv6_Source source;
};

// 4
struct Pim_IPv6_Group_Record {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t rsv;
  uint8_t mask_len;
  click_in6_addr addr;
  uint16_t no_of_joined_sources;
  uint16_t no_of_pruned_sources;
  //  Pim_IPv6_Source sources[1];
};

// 3
struct Pim_IPv6_Join_Prune {
  // Pim_IPv6_Unicast upstream_neighbor;
  uint8_t reserved;
  uint8_t no_of_groups;
  uint16_t holdtime;
  //  IPv6_Group_Record group[1];
};

struct hopbyhopheader {
  unsigned char type;
  unsigned char length;
  unsigned short parameter;
  unsigned int empty;
};

#endif
