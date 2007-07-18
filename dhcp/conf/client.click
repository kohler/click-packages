require(dhcp)

AddressInfo(myeth 00:13:02:99:76:12);
//52:54:00:e5:33:17);

in :: FromDevice(eth0, PROMISC true)
	-> inc :: Classifier(12/0806 20/0001, // ARP queries
			     12/0806 20/0002, // ARP replies
			     12/0800, -);

inc[0] -> Discard;
inc[3] -> Discard;

inc[2] -> Strip(14)
	-> CheckIPHeader
	-> IPPrint("in ")
	-> ipc :: IPClassifier(udp && dst port bootpc, icmp echo-reply)
	-> client :: DHCPClient(myeth, LEASE_CALL release.run)
	-> udpbcast :: UDPIPEncap(0.0.0.0, bootpc, 255.255.255.255, bootps)
	-> eencap :: EtherEncap(0x0800, myeth, ff:ff:ff:ff:ff:ff)
	-> IPPrint(out)
	-> q :: Queue
	-> ToDevice(eth0);

client[1] -> udpucast :: UDPIPEncap(0.0.0.0, bootpc, 255.255.255.255, bootps)
	-> eencap;

ipc[1]	-> ping :: ICMPPingSource(0.0.0.0, 0.0.0.0, ACTIVE false)
	-> IPPrint(png)
	-> arpq :: ARPQuerier(0.0.0.0, myeth)
	-> q;
inc[1] -> [1] arpq;

release :: Script(TYPE PASSIVE,
	print $args,
	write ping.active $1,
	goto end $(not $1),
	write udpucast.src $2,
	write udpucast.dst $3,
	write ping.src $2,
	write ping.dst $3,
	write arpq.ipaddr $2);
