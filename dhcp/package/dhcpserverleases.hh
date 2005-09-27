#ifndef DHCPSSERVERLEASE_HH
#define DHCPSSERVERLEASE_HH

#include <click/element.hh>
#include <click/bighashmap.hh>
#include <click/vector.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>

#include <click/timestamp.hh>

/*
 * =c
 * DHCPServerLeases( ServerIPAddress, SubnetMask )
 *
 * =s 
 * The core of the DHCP Server. Responsible of keeping track of
 * free and allocated leases
 *
 * =d 
 * 
 * DHCPServerLeases is responsible of keeping track of free,
 * reservered, and allocated leases. dhcpd_kscript interacts with
 * DHCPServerLeases with its handlers for bootstrapping and lease
 * committing purposes. 
 * 
 * dhcpd_kscript "cat"s dhcpd.leases file to DHCPServerLeases's
 * dhcpd_leases handler to set up the committed leases upon
 * reboot. Also, dhcpd_kscript "cat"s dhcpd.conf file
 * DHCPServerLeases's dhcpd_conf handler to setup all the default
 * parameters and the free leases.
 *
 * read_free_leases handler discloses the available IPs.
 *
 * read_leases discloses all the existing leases. dhcpd_kscript saves
 * this information periodically. 
 * 
 *   
 * =e
 * DHCPServerLeases(192.168.10.9, 192.168.10.0);
 *
 * =a
 * DHCPServerOffer, DHCPServerACKorNACK, DHCPServerRelease
 *
 */

class DHCPServerLeases : public Element
{
public:
  DHCPServerLeases();
  ~DHCPServerLeases();
  const char* class_name() const { return "DHCPServerLeases"; }
  const char* processing() const { return AGNOSTIC; }
  int initialize(ErrorHandler *);
  int configure( Vector<String> &conf, ErrorHandler *errh );
  void add_handlers();
  void ip_free_list_push_back(const IPAddress &ipAddr);
  bool reserve_any_ip(IPAddress &ipAddr);
  bool reserve_this_ip(const IPAddress &ipAddr);
  uint32_t get_default_duration() const;
  uint32_t get_max_duration() const;
  const IPAddress &get_server_ip_addr() const;
  const IPAddress &get_subnet_mask() const;
  
  Vector<IPAddress> _ip_free_list;
  bool _read_conf_file;
  bool _read_leases_file;
  uint32_t _default_duration;
  uint32_t _max_duration;

  class Lease
  {
  public:
    Lease();
    Lease(const String &ethAddr_str,
	  const String &ipAddr_str,
	  const Timestamp &start_time,
	  const Timestamp &end_time);
    
    Lease(const EtherAddress &etherAddr,
	  const IPAddress &ipAddr,
	  const Timestamp &start_time,
	  const Timestamp &end_time);
    
    ~Lease();
    
    void validate();
    //void setTime(const Timestamp &start_time,
    //const Timestamp &end_time);
    void LeaseExtend();
    const EtherAddress &getEtherAddr() const;
    const IPAddress &getIPAddr() const;
    const Timestamp &getStartTime() const;
    const Timestamp &getEndTime() const;
    const Timestamp &getDuration() const;
    void setIPAddr(const IPAddress &ipAddr);
    const bool is_valid() const;
    
  private:
    EtherAddress _etherAddr;
    IPAddress _ipAddr;
    Timestamp _start_time;
    Timestamp _end_time;
    Timestamp _lease_duration;
    bool _valid;
  };

  Lease* get_client_ip(const EtherAddress &ethAddr);
  bool can_ip_be_reserved(const IPAddress &ipAddr);
  void eth_lease_map_insert(const EtherAddress& ethAddr,
			    Lease *lease);
  void ip_lease_map_insert(const IPAddress &ipAddr,
			   Lease *lease);
  bool eth_lease_map_rm(const EtherAddress &ethAddr);
  bool ip_lease_map_rm(const IPAddress &ipAddr);
  Lease *ip_lease_map_find(const IPAddress &ipAddr);
  Lease *eth_lease_map_find(const EtherAddress &ethaddr);

  String get_allocated_leases_string() const;
  void run_timer(Timer *);
  
private:
  IPAddress _subnet_ip_addr;
  IPAddress _server_ip_addr;
  HashMap<EtherAddress, Lease*> _eth_lease_map;
  HashMap<IPAddress, Lease*> _ip_lease_map;
  Timer _reclaim_lease_timer;
};

#endif
