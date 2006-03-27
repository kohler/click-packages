// 3 port IPv6 router
require(ip6multicast);
//eth5
net1_nda::IP6NDAdvertiser(3ffe:1001:7d0:2::1/64 00:04:23:45:9D:70, fe80::204:23ff:fe45:9d70/64 00:04:23:45:9D:70);
net1_nds::IP6NDSolicitor(fe80::204:23ff:fe45:9d70, 00:04:23:45:9D:70);
//eth0
net2_nda::IP6NDAdvertiser(3ffe:1001:7d0:4::1/64 00:30:48:52:FE:B3, fe80::204:23ff:fe45:9d73/64 00:30:48:52:FE:B3);
net2_nds::IP6NDSolicitor(fe80::230:48ff:fe52:feb3, 00:30:48:52:FE:B3);
//eth3
net3_nda::IP6NDAdvertiser(3ffe:1001:7d0:3::1/64 00:04:23:45:9D:72, fe80::204:23ff:fe45:9d72/128 00:04:23:45:9D:72);
net3_nds::IP6NDSolicitor(fe80::204:23ff:fe45:9d72, 00:04:23:45:9D:72);
	
mld_copy::Tee(); 


pim_ft::IP6PIMForwardingTable(fe80::204:23ff:fe45:9d70 fe80::204:23ff:fe45:9d73 fe80::204:23ff:fe45:9d72);
pim_ctl::IP6PIMControl("pim_ft");
mct :: IP6MulticastTable("pim_ctl");
pim1::IP6PIM("mct", "pim_ft", "pim_ctl", fe80::204:23ff:fe45:9d70);
pim2::IP6PIM("mct", "pim_ft", "pim_ctl", fe80::230:48ff:fe52:feb3);
pim3::IP6PIM("mct", "pim_ft", "pim_ctl", fe80::204:23ff:fe45:9d72);


rt :: LookupIP6Route(
		3ffe:1001:7d0:4::1/128 0,
		3ffe:1001:7d0:3::1/128 0,
		fe80:0000:0000:0000:0204:23ff:feba:d09e/128 3ffe:1001:7d0:2::3 1, // een5212
		3ffe:1001:7d0:2::/64 3ffe:1001:7d0:2::3 1,
		fe80::209:5bff:fee4:237a/128 3ffe:1001:7d0:4::3 2, // notebook pcmcia
		3ffe:1001:7d0:4::/64 3ffe:1001:7d0:4::3 2,
		fe80::204:23ff:fe08:f0a8/128 3ffe:1001:7d0:3::3 3, // een5047
		fe80::204:23ff:fe08:f0a8/128 3ffe:1001:7d0:3::3 3, // een5047
		fe80::204:23ff:fe08:f0a8/128 3ffe:1001:7d0:3::3 3, // een5047
		3ffe:1001:7d0:7::/64 3ffe:1001:7d0:3::3 3,
		3ffe:1001:7d0:6::/64 3ffe:1001:7d0:3::3 3,
		3ffe:1001:7d0:3::/64 3ffe:1001:7d0:3::3 3,
		3ffe:1001:7d0:5::/64 3ffe:1001:7d0:3::3 3,
		0::ffff:0:0/96 ::0 4,
		::0/0 ::c0a8:1 4,
		ff02::1/64 5);

//this classifier divides MLD messages, multicast traffic and other IPv6 packets
mcc :: Classifier(6/11 24/ff, // UDP Multicast traffic
 6/00 40/3a 42/0502, // Hop-by-hop header, ICMP, MLD router alert
 6/67, // PIM
 -);
 



net3_class,net2_class,net1_class::Classifier(12/86dd 20/3aff 54/87,
	         12/86dd 20/3aff 54/88,
			 12/86dd);

net2q,net3q,net1q:: Queue(10);

FromDevice(eth5)
->FrontDropQueue(10)->Unqueue()
->net1_class;
FromDevice(eth0)
->FrontDropQueue(10)->Unqueue()
		->net2_class;
FromDevice(eth3)
->FrontDropQueue(10)->Unqueue()
		->net3_class;

ippath1::Strip(14)
	-> CheckIP6Header(3ffe:1001:7d0:4::ffff 3ffe:1001:7d0:3::ffff 3ffe:1001:7d0:2::ffff)
	-> GetIP6Address(24)
	// -> Print("pim1 gets", 100)
	-> pim1;
	pim1[0]	-> mcc;
	pim1[1]	-> Discard;

ippath2::Strip(14)
	-> CheckIP6Header(3ffe:1001:7d0:4::ffff 3ffe:1001:7d0:3::ffff 3ffe:1001:7d0:2::ffff)
	-> GetIP6Address(24)
//	-> Print("pim2 gets", 100)
	-> pim2;
	
	pim2[0]	-> mcc;
	pim2[1]	-> Discard;

ippath3::Strip(14)
	-> CheckIP6Header(3ffe:1001:7d0:4::ffff 3ffe:1001:7d0:3::ffff 3ffe:1001:7d0:2::ffff)
	-> GetIP6Address(24)
//	-> Print("pim3 gets", 100)
	-> pim3;
	pim3[0]	-> mcc;
	pim3[1]	-> Discard;

net1_class[0]
// received neighbor solicitation
	-> net1_nda
	-> net1q;

net1_class[1] 
// received neighbor advertisement
	-> [1]net1_nds;
net1_class[2] 
// "normal" IP packet

	->ippath1;

mld::MLD("mct");

mld[0] -> Discard;
mld[1] -> rt;

mcc[0] 
//	-> Print("IPv6 multicast") 
	-> mct;


mcc[1] // -> Print("icmp6") 
	-> mld;
mcc[2] -> Discard;
mcc[3] // -> Print("rest") 
	-> rt;

pim_ctl[0]-> rt;

mct[0] -> rt;
mct[1]// -> Print("IPv6 multicast going to PIM-ft") 
	-> pim_ft;

pim_ft[0] //->Print("pim_ft active")
	->rt;

net2_class[0]
// received neighbor solicitation
	-> net2_nda
	-> net2q;

net2_class[1] 
// received neighbor advertisement
	-> [1]net2_nds;
net2_class[2] 
// "normal" IP packet
	-> ippath2;

net3_class[0]
// received neighbor solicitation
	-> net3_nda
	-> net3q;

net3_class[1] 
// received neighbor advertisement
	-> [1]net3_nds;
net3_class[2] 
// "normal" IP packet
	-> ippath3;

rt[0] -> Print("rt discard", 90)->Discard;
rt[1]//  -> Print("rt port 1 active", 100) 
	->ipc1::Classifier(6/11 24/ff, -);
	ipc1[0]->IP6MulticastEtherEncap(0x86dd, 00:04:23:45:9D:70) -> net1q;
	ipc1[1]
	-> FixIP6Src(fe80::204:23ff:fe45:9d70)
	-> IP6FixPIMSource(fe80::204:23ff:fe45:9d70, "pim_ft")
	-> DecIP6HLIM
//	-> ICMP6Checksum()
	-> [0]net1_nds;
rt[2] // -> Print("rt port 2 active", 0) 
	->ipc2::Classifier(6/11 24/ff, -);
	ipc2[0]->IP6MulticastEtherEncap(0x86dd, 00:30:48:52:FE:B3) -> net2q;
	ipc2[1]
	-> FixIP6Src(fe80::230:48ff:fe52:feb3)
	-> IP6FixPIMSource(fe80::230:48ff:fe52:feb3, "pim_ft")
	-> DecIP6HLIM
//	-> ICMP6Checksum()
	-> [0]net2_nds;
rt[3] // -> Print("rt port 3 active", 0) 
	->ipc3::Classifier(6/11 24/ff, -);
	ipc3[0]->IP6MulticastEtherEncap(0x86dd, 00:04:23:45:9D:72) -> net3q;
	ipc3[1]
	-> FixIP6Src(fe80::204:23ff:fe45:9d72)
	-> IP6FixPIMSource(fe80::204:23ff:fe45:9d72, "pim_ft")
	-> DecIP6HLIM
//	-> ICMP6Checksum()
	-> [0]net3_nds;
rt[4] // -> Print("going to litter bin", 96)
	-> Discard;


rt[5] -> mld_copy;

mld_copy[0] -> FixIP6Src(fe80::204:23ff:fe45:9d70) -> IP6FixPIMSource(fe80::204:23ff:fe45:9d70, "pim_ft") 
-> ICMP6Checksum() 
-> EtherEncap(0x86dd, 00:04:23:45:9D:70, 33:33:00:00:00:02) 
-> net1q;
mld_copy[1] -> FixIP6Src(fe80::230:48ff:fe52:feb3) -> IP6FixPIMSource(fe80::230:48ff:fe52:feb3, "pim_ft")
-> ICMP6Checksum()
-> EtherEncap(0x86dd, 00:30:48:52:FE:B3, 33:33:00:00:00:02) 
-> net2q;
mld_copy[2]  -> FixIP6Src(fe80::204:23ff:fe45:9d72)-> IP6FixPIMSource(fe80::204:23ff:fe45:9d72, "pim_ft")
-> ICMP6Checksum() 
-> EtherEncap(0x86dd, 00:04:23:45:9D:72, 33:33:00:00:00:02) 
-> net3q;

net1_nds[0] 
	-> net1q;
net2_nds[0] 
	-> net2q;
net3_nds[0] 
	-> net3q;

net3q // -> Print("eth3 active") 
-> ToDevice(eth3);
net2q // -> Print("eth0 active") 
-> ToDevice(eth0);
net1q // -> Print("eth5 active") 
-> ToDevice(eth5);