require(dhcp)

udp_encap::UDPIPEncap( 192.168.10.10, 67, 255.255.255.255, 68 );
eth_encap::EtherEncap( 0x0800, 52:54:00:E5:33:17 , ff:ff:ff:ff:ff:ff);
	
server :: DHCPServerLeases( 192.168.10.10 , 192.168.10.0);

FromDevice(eth0)
	-> Strip(14)
	-> Align(4, 0)
	-> ip_check::CheckIPHeader(CHECKSUM true)
	-> udp_check::CheckUDPHeader
	-> ipclass :: IPClassifier(icmp type echo-reply, -)

ipclass[0] 
	-> Print("ICMP ECHO REPLY") 
	-> [1]serverOffer::DHCPServerOffer(server);

ipclass[1]
	-> CheckDHCPMsg(request)
	-> class :: DHCPClassifier( discover, request, release, -)

class[0] -> Print(DISCOVER) 
	 -> [0]serverOffer 

class[1] -> Print(REQUEST)  
	 -> DHCPServerACKorNAK(server) -> udp_encap -> eth_encap-> q::Queue(1000)->to_dev::ToDevice(eth0);

class[2] -> Print(RELEASE) 
	 -> DHCPServerRelease(server);
	 
class[3] -> Print(OTHER) -> Discard;

serverOffer[0]-> udp_encap -> eth_encap-> q;
serverOffer[1]-> icmpEncap::ICMPPingEncap(192.168.10.10, 255.255.255.255) 
	      -> DHCP_ICMP_Encap(serverOffer.dhcp_icmp_ping_src, serverOffer.dhcp_icmp_ping_dst)
              -> q; 


//DriverManager(
//	wait_time 2s,
//	write server.dhcpd_leases lease 192.168.10.128 { 
//					starts 1130180078 
//					ends 1130180090 
//					hardware ethernet 52:54:00:e5:33:17 },
//	wait_time 2s,
//	write server.dhcpd_conf range dynamic-bootp 192.168.10.128 192.168.10.254 default-lease-time 30 max-lease-time 60,
//	write server.dhcpd_conf 
//subnet 192.168.10.0 netmask 255.255.255.0{
//	option routers 192.168.10.1
//	option subnet-mask 255.255.255.0
//	range dynamic-bootp 192.168.10.128 192.168.10.254
//	default-lease-time 30
//	max-lease-time 60
//},

////subnet 192.168.10.0 netmask 255.255.255.0 { 
////	option routers 192.168.10.1 
////	option subnet-mask 255.255.255.0 
////	range dynamic-bootp 192.168.10.128 192.168.10.254 
////	default-lease-time 30 
////	max-lease-time 60 
////}, 
//	save server.read_free_leases out.dump,
//	wait_time 10s,
//	save server.read_leases dhcpd.leases,
//	loop);	
