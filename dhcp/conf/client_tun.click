require(dhcp)

tun :: KernelTun(2.0.0.1/8);
tunq :: IPEncap(4, 2.0.0.2, 1.0.0.2)->Queue->tun;
udp_encap::UDPIPEncap(255.255.255.255, 68, 255.255.255.255, 67);
eth_encap::EtherEncap(0x0800, 1:2:3:4:5:6, ff:ff:ff:ff:ff:ff);

client::DHCPClient(1:2:3:4:5:6, LEASE_CALL newlease.run);

tun -> IPPrint(<Client>)
    -> StripIPHeader
    -> Strip(14)
    -> Align(4, 0)
    -> CheckIPHeader(CHECKSUM true)
    -> CheckUDPHeader
    -> CheckDHCPMsg(reply)
    -> [0]client;
	
client[0] -> Print(<dhcpMsg>)
          -> udp_encap
	  -> eth_encap
	  -> tunq;
	
client[1] -> udp_encap1::UDPIPEncap( 192.168.10.10 , 68, 192.168.10.9, 67 )
	  -> eth_encap -> tunq;
	
newlease :: Script(TYPE PASSIVE,
	goto end $(not $1),
	write udp_encap1.src $2,
	write udp_encap1.dst $3,
	write udp_encap.src $2,
	write udp_encap.dst $3)
