//
// egress.click
// Mark Huang <mlhuang@cs.princeton.edu>
//
// This is a Click configuration for egress node of an
// IP-in-GRE-in-UDP-in-IP overlay network on PlanetLab. The overlay
// network is actually composed of two distinct networks: a PPP
// network of 1 local PPP concentrator and 2 remote PPP clients, and
// an IP network that is fully connected in a static routing
// scheme. For convenience, the overlay IP addresses are the same as
// the real IP addresses of the nodes participating in the overlay.
//
// This configuration provides NAT between the overlay and the outside
// world. Packets on the overlay destined for IP addresses outside the
// overlay, are routed to this configuration, the egress node for the
// overlay network.
//
// Copyright (c) 2004  The Trustees of Princeton University (Trustees).
//
// $Id: egress.click,v 1.1 2004/04/17 15:26:11 mhuang Exp $
//

require(gre)

AddressInfo(
	alice		128.112.139.80	128.112.139.80/32,
	intern		10.0.0.0/8	10.0.0.0/8,
	planetlab-1	128.112.139.71	128.112.139.71/32,
	planetlab-2	128.112.139.72	128.112.139.72/32,
	planetlab-3	128.112.139.73	128.112.139.73/32,
	default		0.0.0.0/0	0.0.0.0/0,
);

// Shared IP input path and routing table
ip :: CheckIPHeader(INTERFACES planetlab-1)
rt :: StaticIPLookup(
	planetlab-1			0,
	planetlab-2			1,
	planetlab-3			2,
	alice				3,
	intern		alice		3,
	default				4
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
	-> ping :: IPClassifier(icmp type echo, -)
ping[0]
	-> ICMPPingResponder
	-> rt
ping[1]
	-> Print("toh")
	-> Discard

// Forwarding paths
rt[1]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-2, 47)
rt[2]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, planetlab-3, 47)
rt[3]
	-> GREEncap(0x0800)
	-> ToSocket(UDP, alice, 47)

// Output paths

IPRewriterPatterns(to_world_pat planetlab-1 50000-65535 - -)

rw :: IPRewriter(
	// internal traffic to outside world
	pattern to_world_pat 0 1,
	drop
);

af :: AggregateIPFlows(TRACEINFO -)
	-> cp :: CheckPaint(0)

// Find mappings for incoming packets from external network
socket :: IPFlowSockets(NOTIFIER af)
	-> CheckIPHeader(INTERFACES planetlab-1)
	-> IPClassifier(tcp or udp)
	-> [1]rw

// Route back to internal network
rw[1]
	-> af
cp[1]
	-> ip
	-> rt

// Masquerade outgoing packets from internal network
rt[4]
	-> SetTimestamp
	-> af
cp[0]
	-> [0]rw

// NAT
rw[0]
	-> GetIPAddress(16)
	-> CheckIPHeader
	-> socket
