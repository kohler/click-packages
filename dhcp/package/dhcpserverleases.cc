#include <click/config.h>
// include your own config.h if appropriate
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "dhcpoptionutil.hh"
#include "dhcpserverleases.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/etheraddress.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/bighashmap.cc>
#include <click/vector.cc>
#include <click/straccum.hh>
#define DEBUG 

DHCPServerLeases::DHCPServerLeases()
    : _read_conf_file(false),
      _read_leases_file(false),
      _reclaim_lease_timer(this)
{
  
}

DHCPServerLeases::~DHCPServerLeases()
{
  
}

int
DHCPServerLeases::configure( Vector<String> &conf, ErrorHandler *errh )
{
  if( cp_va_parse(conf, this, errh,
		  cpIPAddress, "server IP address", &_server_ip_addr,
		  cpIPAddress, "subnet ip mask", &_subnet_ip_addr,
		  cpEnd) < 0 )
  {
    return -1;
  }
  return 0;
}


int 
DHCPServerLeases::initialize(ErrorHandler *)
{
  _reclaim_lease_timer.initialize(this);
  return 0;
}

void 
DHCPServerLeases::run_timer(Timer *)
{
  Timestamp now = Timestamp::now();
  
  HashMap< IPAddress, Lease* >::iterator iter = _ip_lease_map.begin();
  for(; iter; ++iter)
  {
    Lease *lease = iter.value();
    if( now > lease->getEndTime())
    {
      Timestamp diff = now - lease->getEndTime();
      if(diff.sec() > 3600)
      {
	_ip_lease_map.remove(lease->getIPAddr());
	_eth_lease_map.remove(lease->getEtherAddr());
      }
    }
  }// for
}

DHCPServerLeases::Lease *
DHCPServerLeases::get_client_ip(const EtherAddress &ethAddr)
{
  DHCPServerLeases::Lease *r = NULL;
  r = _eth_lease_map.find(ethAddr);
  return r;
}

bool
DHCPServerLeases::can_ip_be_reserved(const IPAddress &ipAddr)
{
  DHCPServerLeases::Lease *r = NULL;
  r = _ip_lease_map.find(ipAddr);
  if( r != NULL )
    return false;
  
  //working on this. 
  // TODO see if ipaddr is in the free iplist
  int size = _ip_free_list.size();
  for(int i =0 ; i < size; i++)
  {
    if( _ip_free_list[i] == ipAddr )
    {
      return true;
    }
  }
  
  return false;
}

bool
DHCPServerLeases::reserve_any_ip(IPAddress &ipAddr)
{
  if(_ip_free_list.empty())
    return false;
  
  ipAddr = 
    _ip_free_list[_ip_free_list.size()-1];
  _ip_free_list.pop_back();
  
  return true;
}


bool
DHCPServerLeases::reserve_this_ip(const IPAddress &ipAddr)
{
  int size = _ip_free_list.size();
  for( int i = 0; i < size; i++ )
  {
    if(_ip_free_list[i] == ipAddr )
    {
      _ip_free_list[i] = _ip_free_list[size-1];
      _ip_free_list.pop_back();
      return true;
    }
  } 
  return false;
}

uint32_t 
DHCPServerLeases::get_default_duration() const
{
  return _default_duration;
}

uint32_t 
DHCPServerLeases::get_max_duration() const
{
  return _max_duration;
}

void 
DHCPServerLeases::eth_lease_map_insert(const EtherAddress& ethAddr,
				       DHCPServerLeases::Lease *lease)
{
  _eth_lease_map.insert(ethAddr, lease);
}

void 
DHCPServerLeases::ip_lease_map_insert(const IPAddress &ipAddr,
				      DHCPServerLeases::Lease *lease)
{
  _ip_lease_map.insert(ipAddr, lease);
}

bool 
DHCPServerLeases::eth_lease_map_rm(const EtherAddress &ethAddr)
{
  return _eth_lease_map.remove(ethAddr);
}

bool 
DHCPServerLeases::ip_lease_map_rm(const IPAddress &ipAddr)
{
  return _ip_lease_map.remove(ipAddr);
}

const IPAddress &
DHCPServerLeases::get_server_ip_addr() const
{
  return _server_ip_addr;
}

const IPAddress &
DHCPServerLeases::get_subnet_mask() const
{
  return _subnet_ip_addr;
}

DHCPServerLeases::Lease *
DHCPServerLeases::ip_lease_map_find(const IPAddress &ipAddr)
{
  return _ip_lease_map.find(ipAddr);
}

DHCPServerLeases::Lease *
DHCPServerLeases::eth_lease_map_find(const EtherAddress &ethAddr)
{
  return _eth_lease_map.find(ethAddr);
}

static String
read_handler(Element *e, void *thunk)
{
  DHCPServerLeases *dsl = static_cast<DHCPServerLeases *>(e);

  switch((intptr_t)thunk)
  {
  case 0:
  {
    // free leases
    int size = dsl->_ip_free_list.size();
    StringAccum sa;
    for(int i = 0 ; i < size ; i ++)
    {
      click_chatter("%s", dsl->_ip_free_list[i].unparse().data());
      sa << dsl->_ip_free_list[i].unparse() << "\n";
      //s+= dsl->_ip_free_list[i].unparse() + "\n";
    }
    return sa.take_string();
  }
  case 1:
  {
    // allocated leases
    return dsl->get_allocated_leases_string();
  }
    default:
      return String();
  }
}

// dhcpd_leases should be called first, then dhcpd_conf.
static int
write_handler(const String &data, Element *e, void *thunk, ErrorHandler *)
{
  DHCPServerLeases *dsl = static_cast<DHCPServerLeases *>(e);
  String s = cp_uncomment(data);
  
  switch((intptr_t)thunk)
  {
  case 0:
  {
    if ( !dsl->_read_conf_file )
    {
      // parse conf
      DHCPOptionUtil::StringTokenizer tokenizer(s);
      String token;
    
      while( tokenizer.hasMoreTokens() )
      {
	token = tokenizer.getNextToken();
	cp_eat_space(token);

	click_chatter(">> %s << ", token.data());
	
	if( token == "range" )
	{
	  tokenizer.getNextToken();
	  IPAddress start_ip, end_ip;
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
	  if(!cp_ip_address(token, &start_ip))
	    assert(0);
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
	  if(!cp_ip_address(token, &end_ip))
	    assert(0);

	  click_chatter("start: %s", start_ip.unparse().data());
	  click_chatter("end  : %s", end_ip.unparse().data());

	  const unsigned char *start_data = start_ip.data();
	  const unsigned char *end_data = end_ip.data();

	  for(uint32_t i = 0; (start_data[3] + i) <= (end_data[3]); i++)
	  {
	    char buf[20];
	    sprintf( buf, "%d.%d.%d.%d", 
		     start_data[0], start_data[1], start_data[2], start_data[3]+i );
	    IPAddress next_ip(buf);
	    click_chatter("%s", next_ip.unparse().data());
	    //if( !dsl->_ip_lease_map.find(next_ip) )
	    if(! dsl->ip_lease_map_find(next_ip) )
	      dsl->ip_free_list_push_back(next_ip);
	    else
	      click_chatter("DON'T INSERT IT!!!! :%s", next_ip.unparse().data());
	  }// for
	}
	else if( token == "default-lease-time" )
	{
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
	  //int default_time;
	  if( !cp_unsigned(token, &dsl->_default_duration) )
	    assert(0);
	  click_chatter("default_time: %d", dsl->_default_duration);
	}
	else if( token == "max-lease-time" )
	{
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
	  if( !cp_unsigned(token, &dsl->_max_duration) )
	    assert(0);
	  click_chatter("max_time : %d", dsl->_max_duration);
	}
      }// while
      
      Timestamp ts = Timestamp::now();
      click_chatter("ts : %u", ts.sec());
      dsl->_read_conf_file = true;
    }
    break;
  }
  case 1:
  {
    // parse lease
    if( !dsl->_read_leases_file )
    {
      DHCPOptionUtil::StringTokenizer tokenizer(s);
      String token;
      while( tokenizer.hasMoreTokens() )
      {
	token = tokenizer.getNextToken();
	cp_eat_space(token);
	
	if( token == "lease" )
	{
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG 
	  click_chatter("---> %s", token.data()); // 192.168.10.128
#endif
	  IPAddress lease_ip;
	  cp_ip_address(token, &lease_ip);
	  click_chatter("\tlease_ip: %s", lease_ip.unparse().data());

	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG 
	  click_chatter("---> %s", token.data()); // {
#endif
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
	  click_chatter("---> %s", token.data()); // starts 

	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG 
	  click_chatter("---> %s", token.data()); // 1110180078
#endif
	  uint32_t start_time;
	  cp_unsigned(token, &start_time);
	  click_chatter("\tstart_time : %u", start_time);
	
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG 
	  click_chatter("---> %s", token.data()); // ends
#endif	
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG 
	  click_chatter("---> %s", token.data()); // 1110180090
#endif
	  uint32_t end_time;
	  cp_unsigned(token, &end_time);
	  click_chatter("\tend_time : %u", end_time);

	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG 
	  click_chatter("---> %s", token.data()); // hardware
#endif
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG
	  click_chatter("---> %s", token.data()); // ethernet
#endif
	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG
	  click_chatter("---> %s", token.data()); // 52:54:00:e5:33:17
#endif
	  EtherAddress etherAddr;
	  cp_ethernet_address(token, &etherAddr); 
	  click_chatter("\tether_addr: %s", etherAddr.unparse().data());

	  token = tokenizer.getNextToken();
	  cp_eat_space(token);
#ifdef DEBUG
	  click_chatter("---> %s", token.data()); // }
#endif
	  
	  if( Timestamp::now().sec() < end_time )
	  {
	    click_chatter("VALID LEASE");
	    DHCPServerLeases::Lease *lease = 
	      new DHCPServerLeases::Lease( etherAddr,
					   lease_ip,
					   Timestamp(start_time , 0),
					   Timestamp(end_time , 0) );
	    lease->validate();
	    dsl->eth_lease_map_insert(etherAddr, lease);
	    dsl->ip_lease_map_insert(lease_ip, lease);
	  }
	}
      }// while
      dsl->_read_leases_file = true;
      break;
    }

  }// switch
  }
  return 0;
}

void 
DHCPServerLeases::ip_free_list_push_back(const IPAddress &ipAddr)
  {
  _ip_free_list.push_back(ipAddr);
}

void 
DHCPServerLeases::add_handlers()
{
  add_write_handler("dhcpd_conf", write_handler, (void*) 0);
  add_write_handler("dhcpd_leases", write_handler, (void*) 1);
  add_read_handler("read_free_leases", read_handler, (void*) 0);
  add_read_handler("read_leases", read_handler, (void*) 1);
}

String 
DHCPServerLeases::get_allocated_leases_string() const
{
  StringAccum sa;
  
  HashMap< IPAddress, Lease* >::const_iterator iter = _ip_lease_map.begin();
  for(; iter; ++iter)
  {
    Lease *lease = iter.value();
    if(lease->is_valid())
    {
      sa << "lease " << lease->getIPAddr().unparse() << " {\n"
	 << "\tstarts " << lease->getStartTime().sec() << "\n"
	 << "\tends " << lease->getEndTime().sec() << "\n"
	 << "\thardware ethernet " << lease->getEtherAddr().unparse() << "\n" 
	 << "}\n";
    }
  }// for
  return sa.take_string();
}

DHCPServerLeases :: Lease :: Lease()
{
  
}

DHCPServerLeases :: Lease :: Lease( const String &ethAddr_str,
				    const String &ipAddr_str,
				    const Timestamp &start_time,
				    const Timestamp &end_time )
    :_start_time(start_time.sec(), start_time.subsec()),
     _end_time(end_time.sec(), end_time.subsec()),
     _lease_duration(end_time.sec() - start_time.sec(), 0),
     _valid(false)
{
  cp_ip_address(ipAddr_str, &_ipAddr);
  cp_ethernet_address(ethAddr_str, &_etherAddr);
}
  
DHCPServerLeases :: Lease :: Lease( const EtherAddress &etherAddr,
				    const IPAddress &ipAddr,
				    const Timestamp &start_time,
				    const Timestamp &end_time)
    : _etherAddr(etherAddr.data()),
      _ipAddr(ipAddr.addr()),
      _start_time(start_time.sec(), start_time.subsec()),
      _end_time(end_time.sec(), end_time.subsec()),
      _lease_duration(end_time.sec() - start_time.sec(), 0),
      _valid(false)
{
  
}

DHCPServerLeases :: Lease :: ~Lease()
{
  
}

void
DHCPServerLeases :: Lease :: validate()
{
  _valid = true;
}

void
DHCPServerLeases :: Lease :: LeaseExtend()
{
  Timestamp now = Timestamp::now();
  _start_time.set_sec(now.sec());
  _start_time.set_subsec(now.subsec());
  _end_time.set_sec( _start_time.sec() + now.sec() );
  _end_time.set_subsec( _start_time.subsec() + now.subsec() );
}

const EtherAddress &
DHCPServerLeases :: Lease :: getEtherAddr() const
{
  return _etherAddr;
}

const IPAddress &
DHCPServerLeases :: Lease :: getIPAddr() const
{
  return _ipAddr;
}

const Timestamp &
DHCPServerLeases :: Lease :: getStartTime() const
{
  return _start_time;
}

const Timestamp &
DHCPServerLeases :: Lease :: getEndTime() const
{
  return _end_time;
}

const bool 
DHCPServerLeases :: Lease :: is_valid() const
{
  return _valid;
}

const Timestamp &
DHCPServerLeases :: Lease :: getDuration() const
{
  return _lease_duration;
}

void 
DHCPServerLeases :: Lease :: setIPAddr(const IPAddress &ipAddr)
{
  _ipAddr = ipAddr;
}

EXPORT_ELEMENT(DHCPServerLeases)
