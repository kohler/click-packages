#ifndef LEASEHASH_HH
#define LEASEHASH_HH

#include <click/element.hh>
#include <click/bighashmap.hh>
#include <click/vector.hh>
#include <click/dequeue.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>

#include <click/timestamp.hh>
#include "leasetable.hh"
/*
 * =c
 * LeaseHash( ServerIPAddress, SubnetMask )
 *
 * =s 
 * The core of the DHCP Server. Responsible of keeping track of
 * free and allocated leases
 *
 * =d 
 * 
 * LeaseHash is responsible of keeping track of free,
 * reservered, and allocated leases. 
 *   
 * =e
 * LeaseHash(192.168.10.9, 192.168.10.0);
 *
 * =a
 * DHCPServerOffer, DHCPServerACKorNACK, DHCPServerRelease
 *
 */

class LeaseHash : public LeaseTable
{
public:
  LeaseHash();
  ~LeaseHash();
  const char* class_name() const { return "LeaseHash"; }
  const char* processing() const { return AGNOSTIC; }
  void* cast(const char*);
  int configure(Vector<String> &conf, ErrorHandler *errh);
  void add_handlers();

  uint32_t get_default_duration();
  uint32_t get_max_duration();
  IPAddress get_server_ip_addr();
  IPAddress get_subnet_mask();
  
  void free_list_push(IPAddress);
  IPAddress free_list_pop();

  bool _read_conf_file;
  bool _read_leases_file;
  uint32_t _default_duration;
  uint32_t _max_duration;

  String get_allocated_leases_string() const;

  void remove(IPAddress ip);
  void remove(EtherAddress eth);
  Lease *new_lease(EtherAddress, IPAddress);
  Lease *new_lease_any(EtherAddress);
  IPAddress get_server_ip();
  bool insert(Lease);
  IPAddress hash(EtherAddress);
private:

  IPAddress _subnet;
};

#endif /* LEASEHASH_HH */
