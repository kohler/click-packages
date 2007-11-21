// -*- c-basic-offset: 4 -*-
/*
 * map_trw.{cc,hh} -- An implementation of Usenix Security approximate TRW
 * Nicholas Weaver
 *
 * This element uses two inputs and two (or four) outputs.  It passively
 * maps the local network to determine which side a host is on, and
 * uses approximate TRW to track hosts and scanners.
 *
 *
 */

// This file is copyright 2005/2006 by the International Computer
// Science Institute.  It can be used for any purposes
// (Berkeley-liscence) as long as this notice remains intact.

// THERE IS NO WARANTEE ON THIS CODE!



#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <clicknet/icmp.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "map_trw.hh"
#include "rc5.hh"
#include "trw_packet_utils.hh"
#include <clicknet/ether.h>
#include <click/etheraddress.hh>

#define FIND_SRC 0
#define FIND_DST 1


// This is for the map of the LOCAL area network.
struct map_record {

    // The IP address for this MAP record.
    IPAddress map_ip;

    // The ethernet discovered for this IP.
    // Not currently used (except for debugging)
    // but no reason not to record this.
    EtherAddress map_eth;

    // The last time this was checked as valid (seconds)
    // O is invalid.  > age is ignored.  Age - 60 is always
    // remapped.  This way, the difference between passive and
    // active can be recorded.
    unsigned last_valid;

    // which port the system is on
    int port;

    // Was this updated passively?
    bool passive_update;

    // Should this system be whitelisted from ARP scanning (the
    // gateway)
    bool arp_whitelist;

};

struct ip_record {
    uint16_t ip_tag;    // Uses the Usenix Security tag/value trick
    int8_t count;       // Count can only go +127/-127, but the floor
                        // is less anyway.  
                        // -128 has a special meaning: the 
                        // entry is invalid and not yet initialized.
    int8_t passive_count; // A count for when passive mapping only
                          // is used.

    uint8_t timestamp;  // Rather than the usenix security
                              // technique of scrubbing on a fixed
                              // timeschedule, instead each entry
                              // has a timestamp associated with it
                              // on a 1 minute granularity.
                              // 
                              // This does introduce a SLIGHT
                              // error, if an IP is idle for >255 minutes
                              // (~4 hours), when reexamined it will
                              // be as if the system was idle for
                              // only mod 256 minutes.
                              //
                              // In return, this saves a whopping 
                              // 50% in memory usage assuming structs
                              // are compiled to word aligned!
                              //
                              // I may add an incremental scrubber later
                              // which every 10 minutes does a scrub & update
};

// Also, unlike the Usenix paper, a common table is used for addresses on
// either side of the filter.  

// Rather, each record is looked up for "SRC" or "DST"
struct con_record {
    uint8_t status;   // Status bits & meaning
                      // Bit 0: Estabished out & allowed
                      // Bit 1: Response established & allowed
                      // Bit 2: Blocked but attempted.
    uint8_t timestamp;
};




CLICK_DECLS

MapTRW::MapTRW()
{
    // MOD_INC_USE_COUNT;
}

MapTRW::~MapTRW()
{
    
    // MOD_DEC_USE_COUNT;
}


void 
MapTRW::handle_arp(int port, Packet *p){
    click_ether *e = (click_ether *) p->data();
    click_ether_arp *ea = (click_ether_arp *) (e + 1);
    unsigned int tpa, spa;
    memcpy(&tpa, ea->arp_tpa, 4);
    memcpy(&spa, ea->arp_spa, 4);
    IPAddress dst = IPAddress(tpa);
    IPAddress src = IPAddress(spa);
    passive_update_map_arp(port,p);


    // Ignore ARPs two/from the gateway system.
    // Currently assumed to be .1 on the subnet
    // (but should change to specify gateway systems)
    if( (ntohl(src) ^ ntohl(_my_ip)) < map_size &&
	(ntohl(src) & ~ntohl(_my_mask)) == 1){

    } else if( (ntohl(dst) ^ ntohl(_my_ip)) < map_size &&
	       (ntohl(dst) & ~ntohl(_my_mask)) == 1){

    } else if (p->length() >= sizeof(*e) + sizeof(click_ether_arp) &&
	       ntohs(e->ether_type) == ETHERTYPE_ARP &&
	       ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER &&
	       ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP &&
	       ntohs(ea->ea_hdr.ar_op) == ARPOP_REQUEST) {



	if(supress_broadcast(port,p)){
	    output(port).push(p);
	    return;
	}

	uint32_t src_hash = rc5_encrypt((uint32_t) src, rc5_key);
	uint32_t dst_hash = rc5_encrypt((uint32_t) dst, rc5_key);
	struct ip_record *src_record = find_ip(src_hash);
	struct con_record *src_con = find_con(NULL,src_hash,
					      dst_hash,FIND_SRC);

	if(src_con->status & 0x1){
	    // arp already seen, ignoring.
	} else if(src_record->count >= ip_table_block_count) {
	    // Policy is IF over count, ALL arps are killed
	    if(src_con->status & 0x4){
		// already seen it.  just drop and quit
	    } else {
		// record this attempt and kill
		src_con->status = src_con->status | 0x4;
		src_record->count += 1;
	    }
	    click_chatter("Dropping ARP scan attempt\n");
	    if(noutputs() == 4){
		output(port + 2).push(p);
	    } else {
		p->kill();
	    }
	    return;
	} else {
	    src_con->status = src_con->status | 1;
	    src_record->count += 1;
	}
    } else if(p->length() >= sizeof(*e) + sizeof(click_ether_arp) &&
	      ntohs(e->ether_type) == ETHERTYPE_ARP &&
	      ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER &&
	      ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP &&
	      ntohs(ea->ea_hdr.ar_op) == ARPOP_REPLY) {
	uint32_t src_hash = rc5_encrypt((uint32_t) src, rc5_key);
	uint32_t dst_hash = rc5_encrypt((uint32_t) dst, rc5_key);
	struct ip_record *dst_record = find_ip(dst_hash);
	struct con_record *dst_con = find_con(NULL,src_hash,
					      dst_hash,FIND_DST);
	if(dst_con->status & 0x2){

	} else {
	    dst_con->status = dst_con->status | 0x2;
	    dst_record->count = dst_record->count - 1;
	}
    }

    else {
	click_chatter("Ignoring non request/response ARP packet");
    }


    output(port).push(p);
}

void 
MapTRW::update_map(){
    // Currently doing passive-only updating.
}

void 
MapTRW::passive_update_map_ip(int port, Packet *p){
    click_ether *e = (click_ether *) p->data();
    const click_ip *iph = p->ip_header();
    const Timestamp ts = p->timestamp_anno();
    IPAddress src(iph->ip_src.s_addr);
    EtherAddress shost(e->ether_shost);

    if( (ntohl(src) ^ ntohl(_my_ip)) < map_size){
	int index = (ntohl(src) & ~ntohl(_my_mask));
	if(arp_map[index].port != port ||
	   arp_map[index].map_eth != shost){
	    StringAccum sa;
	    sa << "WARNING!  Host " << src << " / "
	       << shost << " has moved or changed identity" << '\0';
	    if(arp_map[index].last_valid != 0) 
		click_chatter("%s", sa.data());
	    arp_map[index].port = port;
	    arp_map[index].map_ip = src;
	    arp_map[index].map_eth = shost;
	}
	arp_map[index].last_valid = (unsigned) ts.sec();
    } else {

    }

}

void 
MapTRW::passive_update_map_arp(int port, Packet *p){
    click_ether *e = (click_ether *) p->data();
    click_ether_arp *ea = (click_ether_arp *) (e + 1);
    const Timestamp ts = p->timestamp_anno();
    unsigned int spa;
    memcpy(&spa, ea->arp_spa, 4);
    IPAddress src = IPAddress(spa);
    EtherAddress shost(e->ether_shost);
    if( (ntohl(src) ^ ntohl(_my_ip)) < map_size){
	int index = (ntohl(src) & ~ntohl(_my_mask));
	if(arp_map[index].port != port ||
	   arp_map[index].map_eth != shost){
	    StringAccum sa;
	    sa << "WARNING!  Host " << src << " / "
	       << shost << " has moved or changed identity" << '\0';
	    if(arp_map[index].last_valid != 0) 
		click_chatter("%s", sa.data());
	    arp_map[index].port = port;
	    arp_map[index].map_ip = src;
	    arp_map[index].map_eth = shost;
	}
	arp_map[index].last_valid = (unsigned) ts.sec();
    } else {

    }
}



// The rules for supressing broadcast...

// IF packet is broadcast, don't supress.

// IF packet is destined for the local LAN, supress analysis
// IF destination system is on the same side as src system.

// IF packet is NOT destined for the local LAN, supress analysis
// IF src is on the same side as the gateway (assumed to be 
// the [1] index.
bool
MapTRW::supress_broadcast(int port, Packet *p){
    click_ether *e = (click_ether *) p->data();
    click_ether_arp *ea = (click_ether_arp *) (e + 1);
    const click_ip *iph = p->ip_header();
    IPAddress dst;
    if (p->length() >= sizeof(*e) + sizeof(click_ether_arp) &&
        ntohs(e->ether_type) == ETHERTYPE_ARP &&
        ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER &&
        ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP){
	click_ether_arp *ea = (click_ether_arp *) (e + 1);
	unsigned int tpa;
	memcpy(&tpa, ea->arp_tpa, 4);
	dst = IPAddress(tpa);
    } else {
	dst = IPAddress(iph->ip_dst.s_addr);
    }
    if( (ntohl(dst) ^ ntohl(_my_ip)) < map_size){
	unsigned index = (ntohl(dst) & ~ntohl(_my_mask));
	// Don't supress broadcasts from analysis.
	if(index == (map_size - 1)) return false;

	if(arp_map[index].last_valid != 0 &&
	   port == arp_map[index].port){
	    return true;
	}
	return false;
    } else {
	if(arp_map[1].last_valid != 0 &&
	   port == arp_map[1].port){
	    return true;
	}
	return false;
    }
}


void 
MapTRW::push(int port, Packet *p)
{
    const click_ip *iph = p->ip_header();
    const Timestamp ts = p->timestamp_anno();
    click_ether *e = (click_ether *) p->data();
    click_ether_arp *ea = (click_ether_arp *) (e + 1);
    if (last_time == 0 || last_time < (((unsigned) ts.sec()) / 60)){
	last_time = (((unsigned) ts.sec()) / 60);
    }

    // For if the map is updated actively.
    if (last_map == 0 || last_map + 60 < ((unsigned) ts.sec())){
	update_map();	
	last_map = ts.sec();
    }

    if (p->length() >= sizeof(*e) + sizeof(click_ether_arp) &&
        ntohs(e->ether_type) == ETHERTYPE_ARP &&
        ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER &&
        ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP){
	handle_arp(port, p);
	return;
    }

    if (!iph) {
	click_chatter("Not an IP packet.  Dropping\n");
        if(noutputs() == 4){
            output(port + 2).push(p);
        } else {
            p->kill();
        }
        return;
    }

    // Update the passive network map.
    passive_update_map_ip(port, p);
    IPAddress src(iph->ip_src.s_addr);
    IPAddress dst(iph->ip_dst.s_addr);

    if(supress_broadcast(port, p)){
	StringAccum sa;
	sa << "Ignored broadcast from " << src << " to " << dst
	   << " from port " << port << '\0';
	click_chatter("%s", sa.data());
	output(port).push(p);
	return;
    }



    uint32_t src_hash = rc5_encrypt((uint32_t) src, rc5_key);
    uint32_t dst_hash = rc5_encrypt((uint32_t) dst, rc5_key);
    struct ip_record *src_record = find_ip(src_hash);
    struct ip_record *dst_record = find_ip(dst_hash);

    struct con_record *src_con = find_con(p,src_hash,dst_hash,FIND_SRC);
    struct con_record *dst_con = find_con(p,src_hash,dst_hash,FIND_DST);

    bool drop = false;
    // Already allowed packet in this direction
    if(src_con->status & 0x1){
	// However, we don't allow it if its a TCP SYN or UDP
	// if its over the count.
	if( src_record->count >= ip_table_block_count
	    && block_policy(p)){
	    drop = true;
	} 
	else if(dst_con->status & 0x1){
	    // dst already established as well.
	    if(!(dst_con->status & 0x2)){
		dst_con->status = dst_con->status & 0x2;
	    } // just in case of collisions & also multiple
	      // connections
	} else {
	    if(!(dst_con->status & 0x2)){
		dst_con->status = dst_con->status & 0x2;
	    }
	    // Do nothing.  Just pass the packet, another allowed send
	}
    } else {
	if(dst_con->status & 0x1){
	    if(valid_ack(p)){
		// This is an ack packet.  So lower DST's count
		// DST's count only gets recorded if DST hasn't
		// had it ACKEd before
		if(!(dst_con->status & 0x2)){
		    // Need to check the 0x2 flag, because
		    // we don't want to double count acks from
		    // different connections to the same port
		    dst_record->count = dst_record->count - 2;
		    if(dst_record->count < ip_table_min_count){
			dst_record->count = ip_table_min_count;
		    }
		    if(dst_record->count < ip_table_block_count &&
		       !(dst_record->count + 2 < ip_table_block_count)){
			StringAccum sa;
			sa << dst << '\0';
			click_chatter("Now Unblocking IP %s (count)",
				      sa.data());
		    }
		    dst_record->timestamp = (uint8_t) last_time;

		    if(((uint32_t) dst) == 0x3aba96c0 && tomato_chatter) 
			click_chatter("Count decreased to %i for %x",
				      dst_record->count,
				      (uint32_t) dst);
		}
		src_con->status = src_con->status | 0x1;
		dst_con->status = dst_con->status | 0x2;

	    } // Otherwise just pass it as a nonack with no
	      // change in any status
	} else {
	    if(dst_con->status & 0x4){ 
		// Reply to something "dropped" but not dropped
		// due to outline testing.
	    }
	    // This is a NEW connection.
	    else if(src_record->count >= ip_table_block_count){
		// IP already being blocked.
		drop = true;
		if(!(src_con->status & 0x4)){
		    // Not a new attempt, so count it as another failure
		    src_record->count = src_record->count + 1;
		    if(src_record->count > ip_table_max_count){
			src_record->count = ip_table_max_count;
		    }
		    src_record->timestamp = (uint8_t) last_time;
		    src_con->status = src_con->status | 0x4;
		    if(((uint32_t) src) == 0x3aba96c0 && tomato_chatter) 
			click_chatter("Count increased to %i for %x",
				      src_record->count,
				      (uint32_t) src);
		}

	    } else {
		// IP not being blocked, so this is OK, but INCR the count
		src_record->count = src_record->count + 1;
		if(src_record->count == ip_table_block_count){
		    StringAccum sa;
		    sa << src << '\0';
		    click_chatter("Now Blocking IP %s\n",
				  sa.data());
		}
		if(src_record->count > ip_table_max_count){
		    src_record->count = ip_table_max_count;
		}
		src_record->timestamp = (uint8_t) last_time;
		src_con->status = src_con->status | 0x1;
		dst_con->status = dst_con->status | 0x2;
		if(((uint32_t) src) == 0x3aba96c0 && tomato_chatter) 
		    click_chatter("Count increased to %i for %x",
				  src_record->count,
				  (uint32_t) src);
			      
	    }
	}
    }

    if(drop){
	click_chatter("Dropping packet");
	if(noutputs() == 4){
	    output(port + 2).push(p);
	} else{
	    p->kill();
	}
    } else {
	output(port).push(p);
    }
}

// looking up the connection record.  The port is ignored for
// UDP but specified for TCP.
struct con_record *MapTRW::find_con(Packet *p,
				       uint32_t src_hash, 
				       uint32_t dst_hash,
				       int direction){
    uint32_t proto_hash;
    if(p == NULL){
	proto_hash = rc5_encrypt(3,rc5_key);
    } else{
	const click_ip *iph = p->ip_header();
	
	if(iph->ip_p == IP_PROTO_TCP){
	    const click_tcp *tcph = p->tcp_header();
	    uint16_t srcp = ntohs(tcph->th_sport);
	    uint16_t dstp = ntohs(tcph->th_dport);
	    if(direction == FIND_SRC){
		// Note, SRCs are keyed by the DST port!
		proto_hash = rc5_encrypt((uint32_t) dstp, 
					 rc5_key);
	    } else {
		proto_hash = rc5_encrypt((uint32_t) srcp,
					 rc5_key);
	    }
	} else if(iph->ip_p == IP_PROTO_UDP){
	    proto_hash = rc5_encrypt(1,rc5_key);
	} else {
	    proto_hash = rc5_encrypt(2,rc5_key);
	}
    }
    int index;
    if(direction == FIND_SRC){
	index = ((src_hash << 2) ^
		 (src_hash >> 30) ^ 
		 dst_hash ^ proto_hash) % con_table_size;
    }
    else {
	index = (src_hash ^ 
		 (dst_hash << 2) ^
		 (dst_hash >> 30) ^ proto_hash) % con_table_size;
    }

    if( ((uint8_t) last_time) - con_table[index].timestamp 
	>= ((uint8_t) con_table_maxage)){  
	if(con_table[index].status) {
	    // click_chatter("Table aged.  Clearing status\n");
	}
	con_table[index].status = 0;
    }
    con_table[index].timestamp = (uint8_t) last_time;
    return &(con_table[index]);
}


// Performs the lookup for the IP in the ip table.  Note
// that because of the use of encrypted indexing for the lookup,
// host or byte order DOES NOT MATTER as long as it is consistant
// across all lookups.
struct ip_record *MapTRW::find_ip(uint32_t ip_encrypted){
    uint32_t ip_index = ip_encrypted & ip_addr_index_mask; 
    uint16_t ip_tag   = (uint16_t) (ip_encrypted >> ip_addr_tag_shift);
    int i;
    // uint32_t ip = rc5_decrypt(ip_encrypted,rc5_key);
    // click_chatter("IP is %8x, encrypted %8x, index %8x, tag %4x\n",
    // ip, ip_encrypted, ip_index, (uint32_t) ip_tag);
    for(i = 0; i < (int) ip_table_assoc; ++i){
	const int at_index = ip_index * ip_table_assoc + i;
	if(ip_table[at_index].ip_tag == ip_tag){
	    if(ip_table[at_index].count == -128){
		ip_table[at_index].count = 0;
		ip_table[at_index].timestamp = (uint8_t) last_time;
	    }
	    // click_chatter("Found IP %x", 
	    // rc5_decrypt(ip_encrypted, rc5_key));
	    if(ip_table[at_index].count < 0){
		if(((uint8_t) last_time) - ip_table[at_index].timestamp
		   > (uint8_t) ip_table_incr_age){
		    ip_table[at_index].timestamp += 
			ip_table_incr_age;
		    ip_table[at_index].count += 1;
		    // click_chatter("Incrementing count for aging\n");
		    // Cheat and handle multiple agings by doing
		    // a recursive call.
		    return find_ip(ip_encrypted);
		}
	    } else if(ip_table[at_index].count > 0){
		if(((uint8_t) last_time) - ip_table[at_index].timestamp
		   > (uint8_t) ip_table_decr_age){
		    ip_table[at_index].timestamp += 
			ip_table_incr_age;
		    ip_table[at_index].count += -1;
                    if(ip_table[at_index].count + 1 == ip_table_block_count){
                        click_chatter("Now Unblocking IP (age)");
		    }

		    // click_chatter("Decrementing count for aging\n");
		    // Cheat and handle multiple agings by doing
		    // a recursive call.
		    return find_ip(ip_encrypted);
		}
	    }
	    return &(ip_table[at_index]);
	}
    }
    for(i = 0; i < (int) ip_table_assoc; ++i){
	const int at_index = ip_index * ip_table_assoc + i;
	if(ip_table[at_index].count == -128){
	    ip_table[at_index].count = 0;
	    ip_table[at_index].ip_tag = ip_tag;
	    ip_table[at_index].timestamp = 
		(uint8_t) last_time;
	    // click_chatter("Allocated new IP %x", 
	    // rc5_decrypt(ip_encrypted, rc5_key));
	    return &(ip_table[at_index]);
	}
    }
    int min = 127;
    int min_index = 0;
    for(i = 0; i < (int) ip_table_assoc; ++i){
	if(ip_table[ip_index * ip_table_assoc + i].count < min){
	    min = ip_table[ip_index * ip_table_assoc + i].count;
	    min_index = i;
	}
    }
    int evict_index = ip_index * ip_table_assoc + min_index;
    //    click_chatter("Evicting entry for IP %x, count %i, index %i",
    // rc5_decrypt((((uint32_t) 
    // ip_table[evict_index].ip_tag) 
    // << ip_addr_tag_shift)
    // | ip_index, rc5_key),
    // (int) 
    // ip_table[evict_index].count,
    // min_index);
    ip_table[evict_index].count = 0;
    ip_table[evict_index].ip_tag = ip_tag;
    ip_table[evict_index].timestamp =
	(uint8_t) last_time;
    return &(ip_table[evict_index]);
}

int
MapTRW::configure(Vector<String> &conf, ErrorHandler *errh){
    // Setting defaults
    ip_table_size = 262144; // 2^18
    ip_table_assoc = 4;
    con_table_size = 262144; // 2^18
    last_time = 0;
    last_map = 0;
    con_table_maxage = 10; 
    // Default of 10 minutes to remove
    // idle connections

    ip_table_decr_age = 2;     // Every 2 minutes count can go down by 1 if >0
    ip_table_incr_age = 10;    // every 10 minutes count goes up by 1 if < 0
    ip_table_block_count = 10; // Block after 10 scans
    ip_table_max_count = 20;   // count shal not exceed
    ip_table_min_count = -20;  // both positive and negative
    tomato_chatter = false;

    rc5_seed = 0xCAFEBABE;
    click_chatter("Parsing Arguments\n");

    if(cp_va_kparse(conf, this, errh,
		    "PREFIX", cpkP+cpkM, cpIPPrefix, &_my_ip, &_my_mask,
		    "ETH", cpkP+cpkM, cpEthernetAddress, &_my_en,

		    cpKeywords,

		    "TOMATO_CHATTER", 0, cpBool, &tomato_chatter,

		    "IP_TABLE_SIZE", 0, cpUnsigned, &ip_table_size,
		    "IP_TABLE_ASSOC", 0, cpUnsigned, &ip_table_assoc,
		    
		    "IP_TABLE_MAX_COUNT", 0, cpInteger, &ip_table_max_count,
		    
		    "IP_TABLE_MIN_COUNT", 0, cpInteger, &ip_table_min_count,

		    "IP_TABLE_BLOCK_COUNT", 0, cpInteger, &ip_table_block_count,
		    
		    "IP_TABLE_DECR_AGE", 0, cpUnsigned, &ip_table_decr_age,

		    "IP_TABLE_INCR_AGE", 0, cpUnsigned, &ip_table_incr_age,
		    
		    "CON_TABLE_SIZE", 0, cpUnsigned, &con_table_size,
		    
		    "CON_TABLE_AGE", 0, cpUnsigned, &con_table_maxage,
		    cpEnd
		    ) < 0
	
       ){
	click_chatter("Arguments Parse Failure\n");
	return -1;
    } 

    map_size = 1 << (32 - _my_mask.mask_to_prefix_len());
    arp_map = new struct map_record[map_size];

    {
	StringAccum sa;
	sa << _my_ip.unparse_with_mask(_my_mask) << " / " << _my_en 
	   << '\0';
	click_chatter("Arguments Parsed\n");
	click_chatter("My IP/MAC address/mask is %s\n", sa.data());
	click_chatter("# of elements in map is %i\n", map_size);
    }


    for(unsigned i = 0; i < map_size; ++i){
	arp_map[i].last_valid = 0;
	arp_map[i].port = 0;
	arp_map[i].passive_update = false;
	arp_map[i].map_ip = (uint32_t (_my_ip & _my_mask)) + htonl(i);
	if(i == 1){
	    arp_map[i].arp_whitelist = true;
	} else {
	    arp_map[i].arp_whitelist = false;
	}
    }


    if(ip_table_max_count <= 0 || ip_table_max_count > 120
       || ip_table_min_count >= 0 || ip_table_min_count < -120
       || ip_table_block_count > ip_table_max_count 
       || ip_table_block_count <= 0 
       || ip_table_incr_age <= 0 || ip_table_incr_age > 120
       || ip_table_decr_age <= 0 || ip_table_decr_age > 120
       || con_table_maxage <= 0 || con_table_maxage > 120){
	return errh->error("0 < block_count < max_count < 120\n" \
			   "-120 < min_count < 0\n" \
			   "0 < (any ageing) < 120\n");
			   
    }
       

    if(noutputs() != 2 && noutputs() != 4){
	return errh->error("There can only be 2 or 4 outputs for MapTRW");
    }
    if(ninputs() != 2){
	return errh->error("There can only be 2 inputs for MapTRW");
    }

    rc5_key = rc5_keygen(rc5_seed);

    click_chatter("RC5 key is %x\n", rc5_seed);
    click_chatter("RC5 encrypt of 0xFEEDFACE is %x\n", 
		  rc5_encrypt(0xFEEDFACE, rc5_key));
    click_chatter("RC5 D(E(x)) of 0xFEEDFACE is %x\n", 
		  rc5_decrypt(rc5_encrypt(0xFEEDFACE, rc5_key),
			      rc5_key));

    click_chatter("Allocating space for %i entry IP table: %i bytes\n",
		  ip_table_size, sizeof(struct ip_record) * ip_table_size);
    ip_table = new struct ip_record[ip_table_size];
    for(int i = 0; i < (int) ip_table_size; ++i){
	ip_table[i].count = -128;
    }
    
    click_chatter("Allocating space for %i entry connection table: %i bytes\n",
		  con_table_size,
		  sizeof(struct con_record) * con_table_size);
    con_table = new struct con_record[con_table_size];
    for(int i = 0; i < (int) con_table_size; ++i){
	con_table[i].status = 0;
	// Don't need to set the timestamp, as status gets properly
	// zeroed out anyway.
    }

    // The masks remove the need for mod calculations and recalculation
    // when finding the index and tag of an IP address
    ip_addr_index_mask = (ip_table_size / ip_table_assoc) - 1;
    ip_addr_tag_shift = 32;
    for(unsigned i = 1; i < (ip_table_size / ip_table_assoc); i = i * 2){
	ip_addr_tag_shift = ip_addr_tag_shift - 1;
    }
    for(unsigned i = 1; i <= ip_table_assoc; i = i * 2){
	if(ip_table_assoc % i != 0 || ip_table_assoc < 1)
	    return 
		errh->error("Table Size & Associativity must be a power of 2");
    }
    for(unsigned i = 1; i <= ip_table_size; i = i * 2){
	if(ip_table_size % i != 0 || ip_table_size < 1)
	    return 
		errh->error("Table Size & Associativity must be a power of 2");
    }
    if((ip_table_size / ip_table_assoc) < 65536 || ip_addr_tag_shift < 16)
	return 
	    errh->error("Table Size / assoc must be >= 2^16. Was %i",
			(ip_table_size / ip_table_assoc));

    click_chatter("IP index mask is %x\n", ip_addr_index_mask);
    click_chatter("IP tag shift is %i\n",  ip_addr_tag_shift);
    
    click_chatter("IP table associativity is %i\n", ip_table_assoc);

    return 0;
}

void MapTRW::chatter_map(struct map_record &rec){
    StringAccum sa;
    sa << "Map Record for " << rec.map_ip << '\0';
    click_chatter("%s", sa.data());
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(rc5)
EXPORT_ELEMENT(MapTRW)

