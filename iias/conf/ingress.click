//
// ingress.click
// Mark Huang <mlhuang@cs.princeton.edu>
//
// This is a Click configuration for the ingress node of an
// IP-in-GRE-in-UDP-in-IP overlay network on PlanetLab. The overlay
// network is actually composed of two distinct networks: a PPP
// network of 1 local PPP concentrator (this configuration) and 2
// remote PPP clients, and an IP network that is fully connected in a
// static routing scheme. For convenience, the overlay IP addresses
// are the same as the real IP addresses of the nodes participating in
// the overlay.
//
// This configuration routes on the overlay between the PPP and IP
// networks. Packets on the overlay destined for all other IP
// addresses, presumably outside the overlay, are routed to
// planetlab-1, the egress node for the overlay network.
//
// Copyright (c) 2004  The Trustees of Princeton University (Trustees).
//
// $Id: ingress.click,v 1.1 2004/04/17 15:26:11 mhuang Exp $
//

require(ppp,gre)

AddressInfo(
	alice		128.112.139.80	128.112.139.80/32,
	planetlab-1	128.112.139.71	128.112.139.71/32,
	planetlab-2	128.112.139.72	128.112.139.72/32,
	planetlab-3	128.112.139.73	128.112.139.73/32,
	local		10.0.0.1	10.0.0.1/32,
	remote0		10.0.0.100	10.0.0.100/32,
	remote1		10.0.0.101	10.0.0.101/32,
	default		0.0.0.0/0	0.0.0.0/0
);

// Shared IP input path and routing table
ip :: CheckIPHeader(INTERFACES alice local)
rt :: StaticIPLookup(
	alice				0,
	local				0,
	remote0				1,
	remote1				2,
	planetlab-1			3,
	planetlab-2			4,
	planetlab-3			5,
	default		planetlab-1	3
);

pptpd :: PPTPServer(VERBOSE 1)

// ppp0
pptpd[0]
	-> ppp0 :: Classifier(2/0021, 2/8021, -)
ppp0[0]
	-> Strip(4)
	-> ip
	-> rt
ppp0[1]
	-> IPCP(local, remote0, VERBOSE 1)
	-> [0]pptpd
ppp0[2]
	-> LCP(VERBOSE 1)
	-> [0]pptpd

// ppp1
pptpd[1]
	-> ppp1 :: Classifier(2/0021, 2/8021, -)
ppp1[0]
	-> Strip(4)
	-> ip
	-> rt
ppp1[1]
	-> IPCP(local, remote1, VERBOSE 1)
	-> [1]pptpd
ppp1[2]
	-> LCP(VERBOSE 1)
	-> [1]pptpd

// Input path
FromSocket(UDP, 0.0.0.0, 47)
	-> CheckGREHeader
	-> c :: Classifier(2/0800, -)
c[0]
	-> StripGREHeader
	-> ip
	-> rt
c[1]
	-> Print("non-IP")
	-> Discard

// Local delivery
rt[0]
	-> IPReassembler
	-> ipc :: IPClassifier(icmp type echo, -)
ipc[0]
	-> ICMPPingResponder
	-> rt
ipc[1]
	-> Print("non-ICMP")
	-> Discard

// Output paths
rt[1]
	-> PPPEncap(0x0021)
	-> [0]pptpd
rt[2]
	-> PPPEncap(0x0021)
	-> [1]pptpd
rt[3]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-1, 47)
rt[4]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-2, 47)
rt[5]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-3, 47)
