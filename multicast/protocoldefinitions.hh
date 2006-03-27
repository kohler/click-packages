#ifndef PROTOCOLDEFINITIONS_HH
#define PROTOCOLDEFINITIONS_HH

/*******************************************************************************************
 *                                                                                         *
 * PIM protocol headers below                                                              *
 *                                                                                         *
 *******************************************************************************************/
struct IPoptions {
  uint8_t data[4];
};

// position in join/prune message: 0, 4 byte
struct Pim_Header {
  uint8_t ver_type;
  uint8_t reserved;
  uint16_t checksum;
};

struct Pim_Options {
  uint16_t type;
  uint16_t len;
  uint16_t value;
};

struct Pim_longOptions {
  uint16_t type;
  uint16_t len;
  uint32_t value;
};


struct Pim_Register {
  uint16_t bn_reserved;
};

// position in join/prune message:  1, 6 byte
struct Pim_IPv4_Unicast {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint16_t addr[2];
};


struct Pim_IPv4_Group {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t reserved;
  uint8_t mask_len;
  uint32_t addr;
};

// position in join/prune message: 4, 8 byte
struct Pim_IPv4_Source {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t swr;
  uint8_t mask_len;
  uint32_t addr;
};

struct Pim_IPv4_Register_Stop {
  Pim_IPv4_Group group;
  Pim_IPv4_Source source;
};

// position in join/prune message:  3, 8 byte
struct Pim_IPv4_Group_Record {
  uint8_t addr_family;
  uint8_t encoding_type;
  uint8_t swr;
  uint8_t mask_len;
  uint32_t addr;
  uint16_t no_of_joined_sources;
  uint16_t no_of_pruned_sources;
};


// position in join/prune message: 2, 10 byte
struct Pim_IPv4_Join_Prune {
  uint8_t reserved;
  uint8_t no_of_groups;
  uint16_t holdtime;
};


/*******************************************************************************************
 *                                                                                         *
 * IGMP protocol headers below                                                             *
 *                                                                                         *
 *******************************************************************************************/

// IGMPv1 and IGMPv2 messages have to be supported by an IGMPv3 router
struct igmpv1andv2message {
  unsigned char type;
  unsigned char responsetime;
  unsigned short checksum;
  unsigned int group;
};  

// the query is used to detect other routers and the state of connected hosts
struct igmpv3querie {
  unsigned char type;
  unsigned char responsecode;
  unsigned short checksum;
  unsigned int group;
  unsigned char s_and_qrv;
  unsigned char qqic;
  unsigned short no_of_sources;
  unsigned int sources[1];
};

// see RFC 3376 for details
struct grouprecord {
  unsigned char type;
  unsigned char aux_data_len;
  unsigned short no_of_sources;
  unsigned int multicast_address;
  unsigned int sources[1];
};

struct igmpv3report {
  unsigned char type;
  unsigned char reserved;
  unsigned short checksum;
  unsigned short reserved_short;
  unsigned short no_of_grouprecords;
  struct grouprecord grouprecords[1];
};


#endif
