require(snmp);

SNMPOidInfo(clicktest private.244);
SNMPVariableInfo(clicktest.1 Counter32 q.drops);

TimedSource(INTERVAL 0.1s)
	-> q :: Queue(10)
	-> TimedSink(INTERVAL 0.3s);

trapsource :: SNMPTrapSource(SRC 1.0.0.1, SPORT 11111, DST 2.0.0.2,
	       ENTERPRISE clicktest,
	       TRAP qdrops clicktest.1.0)
	-> IPPrint(LABEL trap)
	-> Discard;

sendtrap :: Script(
	init drops 0,
	wait 1s,
	set newdrops $(q.drops),
	goto begin $(eq $drops $newdrops),
	set drops $newdrops,
	write trapsource.send_qdrops,
	goto begin);
