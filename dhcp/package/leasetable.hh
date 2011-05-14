#ifndef LEASETABLE_HH
#define LEASETABLE_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
#include <click/hashtable.hh>
CLICK_DECLS



class Lease {
 public:
	Lease() { }
	~Lease() { }
	
	EtherAddress _eth;
	IPAddress _ip;
	Timestamp _start;
	Timestamp _end;
	Timestamp _duration;
	bool _valid;
	void extend() {
		Timestamp now = Timestamp::now();
		_start.set_sec(now.sec());
		_start.set_subsec(now.subsec());
		_end.set_sec( _start.sec() + now.sec() );
		_end.set_subsec( _start.subsec() + now.subsec() );
	}
};


/*
 * This is basically an abstract classs. If you want to
 * implement your own dhcp lease server, subclass this and 
 * implement new_lease_any and new_lease. See leasepool.cc
 * for an example
 */
class DHCPLeaseTable : public Element {
public:
  DHCPLeaseTable();
  ~DHCPLeaseTable();
  const char* class_name() const { return "DHCPLeaseTable"; }
  void* cast(const char*);
  int configure( Vector<String> &conf, ErrorHandler *errh );
  virtual Lease *lookup(IPAddress ip);
  virtual Lease *rev_lookup(EtherAddress eth);

  virtual void remove(EtherAddress eth);
  virtual Lease *new_lease_any(EtherAddress) {
	click_chatter("%{element}::%s: %s\n", this, __FILE__, __func__);
	  return 0;
  }
  virtual Lease *new_lease(EtherAddress, IPAddress) {
	click_chatter("%{element}::%s: %s\n", this, __FILE__, __func__);
	  return 0;
  }
  virtual bool insert(Lease);


  IPAddress _ip;
  IPAddress _subnet;
  EtherAddress _eth;
  typedef HashTable<IPAddress, Lease> LeaseMap;
  typedef LeaseMap::const_iterator LeaseIter;
  LeaseMap _leases;

  HashTable<EtherAddress, IPAddress> _ips;


  static String read_handler(Element *e, void *thunk);
  void add_handlers();

};

CLICK_ENDDECLS
#endif /* LEASETABLE_HH */
