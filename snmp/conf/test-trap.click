require(snmp);

/* This file demonstrates the use of Click's SNMP support elements. */

/* Part 1: The basic router */

// Send packets from source to sink via a queue.  The queue will quickly
// overflow.
TimedSource(INTERVAL 0.1s)
	-> q :: Queue(10)
	-> TimedSink(INTERVAL 0.3s);


/* Part 2: SNMP support */

// Declare an enterprise OID for our traps.  The enterprise is named
// "clicktest".
SNMPOidInfo(clicktest private.244);

// Declare an SNMP variable binding.  The variable "clicktest.1" -- that is,
// OID "private.244.1", or "1.3.6.1.4.244.1" -- has Counter32 type, and its
// value is found by reading handler "q.drops".
SNMPVariableInfo(clicktest.1 Counter32 q.drops);

// Trap generation path.
trapsource :: SNMPTrapSource(
		// Set UDP/IP source & destination addresses & ports.
		// Default destination port is 162.
		SRC 1.0.0.1, SPORT 11111, DST 2.0.0.2,
		// Enterprise generating the trap.
		ENTERPRISE clicktest,
		// Declare a trap named "qdrops".  This trap's packets
		// will contain variable "clicktest.1.0", which was declared
		// above to correspond to the Queue's "drops" handler.
		// To send the trap, write to the "trapsource.send_qdrops"
		// handler.
		TRAP qdrops clicktest.1.0)
	-> IPPrint(LABEL trap)
	-> Discard; // or try "-> ToDump(foo, ENCAP IP)"

// This Script element directs trap generation by poking "trapsource" when
// drops happen.
sendtrap :: Script(
	init drops 0,				// initialize $drops to 0
	wait 1s,				// wait 1 second
	set newdrops $(q.drops),		// loop if no new drops
	goto begin $(eq $drops $newdrops),
	set drops $newdrops,
	write trapsource.send_qdrops,		// otherwise, send trap
	goto begin);				// and loop
