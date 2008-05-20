#ifndef LEASEPOOL_HH
#define LEASEPOOL_HH

#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/vector.hh>
#include <click/dequeue.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>

#include <click/timestamp.hh>
#include "leasetable.hh"
/*
 * =c
 * DHCPLeasePool(ETH, IP, MASK, I<keywords> )
 *
 * =s DHCP
 * The core of the DHCP Server. Responsible of keeping track of
 * free and allocated leases
 *
 * =d 
 * 
 * LeasePool is responsible of keeping track of free,
 * reservered, and allocated leases. 
 *   
 * =e
 * LeasePool(192.168.10.9, 192.168.10.0);
 *
 * =a
 * DHCPServerOffer, DHCPServerACKorNACK, DHCPServerRelease
 *
 */

class LeasePool : public DHCPLeaseTable
{
public:
  LeasePool();
  ~LeasePool();
  const char* class_name() const { return "DHCPLeasePool"; }
  const char* processing() const { return AGNOSTIC; }
  void* cast(const char*);
  int configure( Vector<String> &conf, ErrorHandler *errh );

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

  void remove(const EtherAddress &eth);
  Lease *new_lease(const EtherAddress &, IPAddress);
  Lease *new_lease_any(const EtherAddress &);
  IPAddress get_server_ip();
  bool insert(Lease);
private:

  DEQueue<IPAddress> _free_list;
  HashTable<IPAddress, IPAddress> _free;

  IPAddress _start;
  IPAddress _end;
};

#endif /* LEASEPOOL_HH */
