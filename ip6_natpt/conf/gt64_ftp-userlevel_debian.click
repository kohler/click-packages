//File: gt64-ftp_debian.click.
//Version: 1.0
//Date: 13/03/2003
//Author: Juan Luis Baptiste M. <juancho@linuxmail.org>

//Configuration file for an IPv6/IPv4 Address Translator with a FTP
//Aplication Level Gateway support.

//This config file is only for use in user level mode, but it can be
//modified to be used with the kernel module. Also it only does static
//translation, but you could easily change the configuration to meet your needs
//in at (AddressTranslator) element.

//Things you have to have present:
//* Translation element at ONLY works correctly with FreeBSD machines as IPv6
//   hosts, there's some problems with Neighboor solicitation and advertisement
//   messages when received from other os'es in the translator, like NetBSD and
//   Linux with 2.4.x kernel.
//* Don't configure IPv6 in the machine running Click, leave the IPv6 module
//  off, as it can make conflicts between Linux IPv6 stack and Click, regarding
//  that Click takes full control of Linux networking functions.

//The network setup for this file is as follows:

//IPv6 Network---------------Address Translator----------------IPv4 Network
// 3ffe:1ce1:2:0:200::2     3ffe:1ce1:2:0:200::1              172.25.79.254
//(1.0.0.1 mapped address)     172.25.79.156

//Things you have to do:
//1. Change IPv6/IPv4 addresses, MAC addresses in IP6NDAdvertiser,
//   IP6NDSolicitor,ARPQuerier and ARPResponder elements.
//2. Change IPv6/IPv4 routes in StaticIPLookup and LookupIP6Route to meet your
//   needs.
//3. Modify the Address Translation element configuration as you need it.
//4. Change CheckIPHeader and CheckIP6Header as you need it.
//5. In the IPv4 host, create a route so all the traffic destined to 1.0.0.1
//   (IPv4 address for the IPv6 host in this case) is sent to the translator, as
//   follows:
//   route add 1.0.0.1 gw 172.25.79.156 eth0 (this is in Linux)
//6. In the IPv6 host, create a route so all the traffic destined to
//   ::172.25.79.254 (IPv4-mapped IPv6 address representing the IPv4 host) is
//   sent to the translator, as follows:
//   route add -inet6 ::172.25.79.254 3ffe:1ce1:2:0:200::1 (this is in FreeBSD)
//7. To start the translator, enter to the userlevel directory and use the
//   command:
//   ./click ../conf/gt64-userlevel.click

//If you have any questions, problems, or better, suggestions of how to improve
//this config file you can send me an email.


elementclass GatewayDevice {
  $device |
  from :: FromDevice($device)
	-> output;
  input -> q :: Queue(1024)
	-> to :: ToDevice($device);
  ScheduleInfo(from .1, to 1);
}

extern_dev :: GatewayDevice(eth1);
intern_dev :: GatewayDevice(eth0);

//Configuration of Neighboor solicitation and advertisement elements for
//comunication with IPv6 hosts.

extern_nda::IP6NDAdvertiser(3ffe:1ce1:2:0:200::1/128 00:E0:7D:E1:BB:E0,
			    3ffe:1ce1:2::/80 00:E0:7D:E1:BB:E0);
extern_nds::IP6NDSolicitor(3ffe:1ce1:2:0:200::1, 00:E0:7D:E1:BB:E0);

//Configuration of ARP elements for comunication with IPv4 hosts.

intern_arp::ARPQuerier(172.25.79.156, 00:10:5A:1C:86:15);
intern_arr::ARPResponder(172.25.79.156 00:10:5A:1C:86:15);

//IPv4 routing table
ipv4rt :: StaticIPLookup(

	172.25.79.156/32 0,
	172.25.79.255/32 0,
	172.25.79.0/32 0,
  192.168.1.2/32 172.25.79.220 1,
	172.25.79.220/32 172.25.79.220 1,
	1.0.0.1/32 1.0.0.1 2,
	0.0.0.0/0 172.25.79.156 3);

//IPv6 routing table
ipv6rt :: LookupIP6Route(
	3ffe:1ce1:2::2/128 ::0 0,
	3ffe:1ce1:2:0:200::1/128 ::0 0,
	3ffe:1ce1:2:0:200::2/128 3ffe:1ce1:2:0:200::2 1,
	3ffe:1ce1:2::/80 ::0 2,
	3ffe:1ce1:2:0:200::/80 ::0 2,
	::0/96 ::0 3,
  	::0/0 ::c0a8:1 4);

//Traffic from IPv4 network
intern_class :: Classifier(
	12/0806 20/0001,  //ARP query messages (output 0)
	12/0806 20/0002, //ARP reply messages (output 1)
	12/0800 30/01000001, //IPv4 packet (output 2)
        -); //??? other packets???

//Traffic from IPv6 network
extern_class :: Classifier(
	12/86dd 20/3aff 54/87, //Neighboor solicitation messages (output 0)
	12/86dd 20/3aff 54/88, //Neighboor advertisement messages (output 1)
	12/86dd,  //IPv6 packet (output 2)
	-); //??? other packets???

//Address Translator configuration
at :: AddressTranslator(
	1,
	0,
	3ffe:1ce1:2:0:200::2 ::1.0.0.1,
	0,
	0,
	0);

//Protocol Translators
pt64 :: ProtocolTranslator64();
pt46 :: ProtocolTranslator46();

//ALG's
tcpAddr:: TCPAddressTranslator(at);
ftp6:: FTPPortMapper6(tcpAddr);

intern_dev
//-> Print(from_eth0, 200)
		->intern_class;

extern_dev
//-> Print(from_eth1, 200)
//		-> Print(before_extern_class,200)
		->extern_class;

extern_class[0]
//-> Print(Neighboor_sol_(0), 200)
//-> Print(before_extern_nda,200)
	-> [0]extern_nda;

extern_class[1]
//-> Print(Neighboor_adv_(1), 200)
//-> Print(1_extern-nds,200)
	-> [1]extern_nds;
extern_class[2]
//-> Print(Normal_IPv6_packet_(2), 200)
	-> Strip(14)
	-> CheckIP6Header(3ffe:1ce1:2:0:200::ffff 3ffe:1ce1:2::ffff)
	-> GetIP6Address(24)
	-> ipv6rt;
extern_class[3]->Discard;

intern_class[0]
//-> Print(ARP_Query_(0), 200)
	-> intern_arr;

intern_class[1]
//-> Print(ARP_Response_(1), 200)
	-> [1]intern_arp;
intern_class[2]
//-> Print(Normal_IPv4_packet_(2), 200)
	-> Strip(14)
	-> CheckIPHeader(172.25.79.255)
	-> GetIPAddress(16)
	-> ipv4rt;
intern_class[3] ->Discard;

ipv6rt[0]
//-> Print(route60-ok, 200)
          -> Discard;
ipv6rt[1]
//-> Print(route61-ok, 200)
	-> extern_dh1:: DecIP6HLIM
//	-> Print(0_extern-nds,200)
	-> [0]extern_nds;
ipv6rt[2] -> extern_dh2:: DecIP6HLIM
//	-> Print(route62-ok, 200)
	-> Discard;
ipv6rt[3]
//-> Print(route63-ok-to_at, 200)
	-> [0]at;
ipv6rt[4]
//-> Print(route64-ok, 200)
          -> Discard;

ipv4rt[0]
//->Print(rt0, 200)
	->Discard;
ipv4rt[1]
//->Print(rt1, 200)
	-> DropBroadcasts
      	-> dt1 :: DecIPTTL
      	-> fr1 :: IPFragmenter(1500)
//	-> Print(before-arp0, 200)
	->[0]intern_arp;

ipv4rt[2]
//->Print(rt2-to_pt46, 200)
	->[0]pt46;
ipv4rt[3]
//->Print(rt3, 200)
	->Discard;

at[0]  	
//-> Print(after-at0, 200)
	-> [0]pt64;
at[1]  	
//-> Print(antes_de_ftp6_1, 200)
-> CheckIP6Header(3ffe:1ce1:2:0:200::ffff 3ffe:1ce1:2::ffff)
  -> [1]ftp6;

pt64[0]
//-> Print(antes_de_ftp6_0, 200)
->CheckIPHeader(172.25.79.255 1.255.255.255)
-> [0]ftp6;

pt46[0]
//-> Print(after-pt460, 200)
	-> [1]at;

ftp6[0]
//->Print(despues_de_ftp6_0,200)
->[0]tcpAddr;
ftp6[1]
//->Print(despues_de_ftp6_1,200)
->[1]tcpAddr;

tcpAddr[0]
//->Print(despues_de_tcpAddr_0,200)
//-> CheckIPHeader(172.25.79.255 1.255.255.255)
	-> GetIPAddress(16)
	-> [0]ipv4rt;

tcpAddr[1]
//->Print(despues_de_tcpAddr_1,200)
//-> CheckIP6Header(3ffe:1ce1:2:0:200::ffff 3ffe:1ce1:2::ffff)
	-> GetIP6Address(24)
	-> [0]ipv6rt;

extern_dh1[1]
//-> Print(icmp_error_extern1, 200)
	-> ICMP6Error(3ffe:1ce1:2:0:200::1, 3, 0)
//	-> Print(0_extern-nds_in_extern_dh1,200)
	-> [0]extern_nds;

extern_nds[0]
//-> Print(extern_nds0-ok, 200)
	-> extern_dev;
extern_nda[0]
//-> Print(extern_nda0-ok, 200)
	-> extern_dev;

intern_arp[0]
//-> Print(arp0, 200)
 	-> intern_dev;
intern_arr[0]
//-> Print(arr0, 200)
 	-> intern_dev;
