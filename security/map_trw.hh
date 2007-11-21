// -*- c-basic-offset: 4 -*-
#ifndef NW_MAP_TRW_HH
#define NW_MAP_TRW_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

// This file is copyright 2005/2006 by the International Computer
// Science Institute.  It can be used for any purposes
// (Berkeley-liscence) as long as this notice remains intact.

// THERE IS NO WARANTEE ON THIS CODE!


/*
 * =c
 * MapTRW(PREFIX, ETH, I<keywords>)
 * =s Packet processing for security
 * This is a packet processor for approximate TRW
 * =d
 * This module implements approximate TRW scan detection.  It is designed
 * to be a push-only module.
 *
 * It takes two input streams and has four output streams.  The first
 * two output streams correspond to the two inputs for normal passing of
 * packets.  The second two output streams are for "dropped" packets,
 * which allows some other module to possibly process and reinject
 * (such as for notification of dropping) 
 *
 * Keyword arguments include the IP table size and the connection table size.
 * 
 * Unlike the usenix description, fields will contain a timestamp
 * with updates performed based on that timestamp.  This is because
 * the usenix experience was that a lot of the range was unused,
 * so rather than housekeeping the table eagerly, more memory will be
 * used to enable lazy housekeeping. 
 *
 * The IP address is used to determine this instance's IP if active mapping
 * (currently not implemneted) is desired and the local subnet.
 * The MASK specifies the subnet mask; combined with the IP
 * Address, this is used to determine whether an IP is local to this LAN
 * or remote (no ARPing needed).
 *
 * ETH is a mac to use for active mapping (not implemented)
 *
 * =a 
 */

class MapTRW : public Element { public:
  
    MapTRW();
    ~MapTRW();
  
    const char *class_name() const	{ return "MapTRW"; }
    const char *processing() const	{ return PUSH; }

    int configure(Vector<String> &conf, ErrorHandler *errh);

    const char * port_count () const {return "2/4";}
    
    void push(int port, Packet *p);
  
private:
    struct ip_record *find_ip(uint32_t ip_hash);
    struct con_record *find_con(Packet *p, uint32_t src_hash,
				uint32_t dst_hash,
				int direction);

    struct ip_record *ip_table;
    struct con_record *con_table;


    struct map_record *arp_map;

    uint16_t *rc5_key;
    uint32_t rc5_seed;

    // Both these are the size and associativity for the
    // two tables.  They will be rounded DOWN to the nearest power of
    // 2.  the ip_table_size must be at least 2^16 * assocativity,
    // 
    // Default values are associativity of 4, table size of 2^18, thus
    // requiring 1 MB by default, and able to store 256k entries
    unsigned ip_table_size;
    unsigned ip_table_assoc;

    unsigned ip_table_decr_age;
    unsigned ip_table_incr_age;
    
    int ip_table_block_count;
    int ip_table_max_count;
    int ip_table_min_count;


    // The size of the connection table.  Default is 2^18 entries
    // which requires 1 MB.
    unsigned con_table_size;

    // The number of idle minutes before a connection table record is aged
    unsigned con_table_maxage;

    // The last time this was accessed, in MINUTES
    unsigned last_time;

    // The last time the table was updated, in SECONDS
    unsigned last_map;

    // The number of entries in the 
    unsigned map_size;

    // Used to get the and index quickly
    uint32_t ip_addr_index_mask;
    uint32_t ip_addr_tag_shift;

    // Controls whether to chatter for tomato
    bool tomato_chatter;


    // The ethernet and IP addresses
    EtherAddress _my_en;
    IPAddress _my_ip;
    IPAddress _my_mask;

    void chatter_map(struct map_record &mp);

    void update_map();
    void handle_arp(int port, Packet *p);

    void passive_update_map_ip(int port, Packet *p);
    void passive_update_map_arp(int port, Packet *p);

    bool supress_broadcast(int port, Packet *p);

};

CLICK_ENDDECLS
#endif
