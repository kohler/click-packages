// 3-port Multicast capable router
// Martin Hoffmann, University of Bristol

// eth0 192.168.30.6 00:30:48:52:FE:B3 this interface is connected to the notebook
// eth3 172.20.12.2 00:04:23:45:9D:72 this interface is connected to een5047 (router)
// eth5 172.20.100.6 00:04:23:45:9D:70 this interface is connected to een5212 (host)

// enable multicast elements
require(multicast);

// define outputs
out0 :: Queue(100) -> todevice0 :: ToDevice(eth0);
out1 :: Queue(100) -> todevice1 :: ToDevice(eth3);
out2 :: Queue(100) -> todevice2 :: ToDevice(eth5);
pimft::PIMForwardingTable(192.168.30.6, 172.20.12.2);
pim_spt::PIMControl("pimft");
igmp:: IGMP("mct");
pim1::PIM("mct", "pimft", "pim_spt", 192.168.30.6);
pim2::PIM("mct", "pimft", "pim_spt", 172.20.12.2);
pim3::PIM("mct", "pimft", "pim_spt", 172.20.100.6);

igmp_query_copy::Tee();

// the routing table is changed slightly in contrast to the unicast router configuration
// interfaces that are wanted to participate in any multicast action need the 224.0.0.1 route to be set
rt :: RadixIPLookup(
	192.168.30.6/32 0,
	192.168.30.255/32 0,
	192.168.30.0/32 0,
	172.20.12.2/32 0,
	172.20.12.255/32 0,
	172.20.12.0/32 0,
	172.20.100.6/32 0,
	172.20.100.255/32 0,
	172.20.100.0/32 0,
	192.168.30.0/255.255.255.0 1,
	172.20.12.0/255.255.255.0 2,
	172.20.100.0/255.255.255.0 3,
	255.255.255.255/32 0.0.0.0 0,
	0.0.0.0/32 0,
	192.168.30.0/255.255.255.0 192.168.30.2 1,
//	192.168.30.5/255.255.255.255 192.168.30.6 1,
	192.168.40.0/255.255.255.0 192.168.30.2 1,
	172.20.12.0/255.255.255.0 172.20.12.1 2,

	192.168.71.0/255.255.255.0 172.20.12.1 2, //straight

//	192.168.71.0/255.255.255.0 192.168.30.2 1, //xorproute
	172.20.6.0/255.255.255.0 172.20.12.1 2,
	172.20.100.0/255.255.255.0 172.20.100.6 3,
	224.0.0.0/27 4);

// ********************************** multicast path begins here ***********

pim_spt[1] -> rt;
pim_spt[0]-> Print("PIM going to be discarded")->Discard;

mct::IPMulticastTable(3, "pim_spt");
//mct::IPMulticastTable();

// the mcc MultiCastClassifier divides multicast packets and igmp packets from unicast ones
mcc::IPClassifier(224.0.0.0/4 and ip proto udp, ip proto igmp, -); //  ip proto pim, -);


// Shared IP input path and routing table


	// if address ranges indicates multicast traffic -> pass to MulticastTable element
	mcc[0] -> mct;
	// if protocol is IGMP then pass packets to IGMP element
	mcc[1] -> igmp;

	// all "normal" IP packets are sent directly to the unicast router
//	mcc[2] -> pim_spt;
	mcc[2] -> rt;

	// the MulticastTable element sets the IP packets address annotation derived from its MulticastForwarding database
    mct[0] -> rt;
	// after copying multicastpackets to all connected hosts send the stream to the pim element
	mct[1] ->pimft;

// make sure that all igmp packets have the right IP source address and forward them to the corresponding interfaces
	
	igmp[1] -> rt;	
	igmp[0] -> Discard;

	pimft->rt;

rt[4] -> igmp_query_copy;


igmp_query_copy[0]  -> FixPIMSource(192.168.30.6, "pimft" ) -> FixIPSrc(192.168.30.6) 
	-> IPMulticastEtherEncap(0x0800, 00:30:48:52:FE:B3) -> out0;
igmp_query_copy[1] -> FixPIMSource(172.20.12.2, "pimft") -> FixIPSrc(172.20.12.2) 
	-> IPMulticastEtherEncap(0x0800, 00:04:23:45:9D:72) -> out1;
igmp_query_copy[2] -> FixPIMSource(172.20.100.6,"pimft" ) -> FixIPSrc(172.20.100.6)
	-> IPMulticastEtherEncap(0x0800, 00:04:23:45:9D:70) -> out2;

// ***************************** unicast paths begin here ***********************
// ARP responses are copied to each ARPQuerier and the host.
arpt :: Tee(4);

// Input and output paths for eth0
c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
FromDevice(eth0) ->FrontDropQueue(100)->Unqueue()-> c0;
c0[0] -> ar0 :: ARPResponder(192.168.30.6 00:30:48:52:FE:B3) -> out0;
arpq0 :: ARPQuerier(192.168.30.6, 00:30:48:52:FE:B3) -> out0;
c0[1] -> arpt;
arpt[0] -> [1]arpq0;
c0[2] -> Paint(0) -> Strip(14) -> CheckIPHeader(INTERFACES 192.168.30.6/32 224.0.0.0/4, VERBOSE true) -> pim1;
pim1[0] -> mcc;
pim1[1] -> Discard;
c0[3] // -> Print("eth0 non-IP") 
	-> Discard;

// Input and output paths for eth3
c1 :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
FromDevice(eth3) ->FrontDropQueue(100)->Unqueue()-> c1;
c1[0] -> ar1 :: ARPResponder(172.20.12.2 00:04:23:45:9D:72) -> out1;
arpq1 :: ARPQuerier(172.20.12.2, 00:04:23:45:9D:72) -> out1;
c1[1] -> arpt;
arpt[1] -> [1]arpq1;
c1[2] -> Paint(1) -> Strip(14) -> CheckIPHeader(INTERFACES 172.20.12.2/32 224.0.0.0/4, VERBOSE true) -> pim2;
pim2[0] -> mcc;
pim2[1] -> Discard;
c1[3] -> Print("eth3 non-IP") -> Discard;

// Input and output paths for eth5
c2 :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
FromDevice(eth5) ->FrontDropQueue(100)->Unqueue()-> c2;
c2[0] -> ar2 :: ARPResponder(172.20.100.6 00:04:23:45:9D:70) -> out2;
arpq2 :: ARPQuerier(172.20.100.6, 00:04:23:45:9D:70) -> out2;
c2[1] -> arpt;
arpt[2] -> [1]arpq2;
c2[2] -> Paint(2) -> Strip(14) -> CheckIPHeader(INTERFACES 172.20.100.6/32 224.0.0.0/4, VERBOSE true) -> pim3; 
pim3[0] -> mcc;
pim3[1] -> Discard;
c2[3] -> Print("eth5 non-IP") -> Discard;

// Local delivery
toh :: Print(toh) -> Discard;
arpt[3] -> toh;
rt[0] -> Print("rtdiscard")->EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> toh;

// Forwarding path for eth0
rt[1] -> ipc0::IPClassifier(224.0.0.0/4 and ip proto udp, -); 
	ipc0[0] -> IPMulticastEtherEncap(0x0800, 00:30:48:52:FE:B3) -> out0;
	ipc0[1] -> FixPIMSource(192.168.30.6, "pimft")

    -> DecIPTTL
    -> FixIPSrc(192.168.30.6)
    -> IPFragmenter(1500)
    -> [0]arpq0;

// Forwarding path for eth3
rt[2] -> ipc1::IPClassifier(224.0.0.0/4 and ip proto udp, -); 
	ipc1[0] -> IPMulticastEtherEncap(0x0800, 00:04:23:45:9D:72) -> out1;
	ipc1[1] 
 	-> FixPIMSource(172.20.12.2, "pimft")

    -> DecIPTTL
    -> FixIPSrc(172.20.12.2)
    -> IPFragmenter(1500)
    -> [0]arpq1;


// Forwarding path for eth5
rt[3]  -> ipc2::IPClassifier(224.0.0.0/4 and ip proto udp, -); 
	ipc2[0] -> IPMulticastEtherEncap(0x0800, 00:04:23:45:9D:70) -> out2;
	ipc2[1]

	-> FixPIMSource(172.20.100.6,"pimft" ) 
    -> DecIPTTL
    -> FixIPSrc(172.20.100.6)

    -> fr2 :: IPFragmenter(1500)
    -> [0]arpq2;

