//
// router.click
// Mark Huang <mlhuang@cs.princeton.edu>
//
// This is a Click configuration for a router on an
// IP-in-GRE-in-UDP-in-IP overlay network on PlanetLab. The overlay
// network is actually composed of two distinct networks: a PPP
// network of 1 local PPP concentrator and 2 remote PPP clients, and
// an IP network that is fully connected in a static routing
// scheme. For convenience, the overlay IP addresses are the same as
// the real IP addresses of the nodes participating in the overlay.
//
// This configuration provides simple routing on the overlay. The
// default route in this configuration is via the ingress node.
//
// Copyright (c) 2004  The Trustees of Princeton University (Trustees).
//
// $Id: router.click,v 1.1 2004/04/17 15:26:11 mhuang Exp $
//

require(ppp,gre)

AddressInfo(
	alice		128.112.139.80	128.112.139.80/32,
	planetlab-1	128.112.139.71	128.112.139.71/32,
	planetlab-2	128.112.139.72	128.112.139.72/32,
	planetlab-3	128.112.139.73	128.112.139.73/32,
	default		0.0.0.0/0	0.0.0.0/0,
);


// Shared IP input path and routing table
ip :: CheckIPHeader(INTERFACES planetlab-2)
rt :: StaticIPLookup(
	planetlab-2			0,
	planetlab-1			1,
	planetlab-3			2,
	alice				3,
	default		alice		3
);

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
	-> Print("toh")
	-> Discard

// Output paths
rt[1]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-1, 47)
rt[2]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-3, 47)
rt[3]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, alice, 47)
